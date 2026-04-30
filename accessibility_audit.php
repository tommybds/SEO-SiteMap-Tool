<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
require __DIR__ . '/auth.php';
ensure_storage_dirs();
auth_session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('accessibility_audit_run', $ip, 18, 600);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit audit accessibilite atteint. Reessaye plus tard.',
        'retry_after' => $limit['retry_after'],
    ], 429);
}

$input = array_merge($_POST, get_json_input());
$url = trim((string) ($input['url'] ?? ''));
if ($url === '') {
    respond_json(['error' => 'Le champ url est obligatoire.'], 400);
}

$validationError = '';
if (!validate_public_url($url, $validationError)) {
    respond_json(['error' => $validationError], 400);
}

scan_history_log('accessibility_audit', $url);

$timeout = clamp_int($input['timeout'] ?? 12, 3, 30, 12);
$requestedStandard = strtolower(trim((string) ($input['standard'] ?? 'rgaa4')));
$referenceStandard = in_array($requestedStandard, ['rgaa4', 'rgaa5'], true) ? $requestedStandard : 'rgaa4';
$maxRedirects = 8;

if (!function_exists('curl_init')) {
    respond_json(['error' => 'cURL est indisponible sur cet hebergement.'], 500);
}

function a11y_to_lower(string $value): string
{
    if (function_exists('mb_strtolower')) {
        return mb_strtolower($value, 'UTF-8');
    }
    return strtolower($value);
}

function a11y_parse_header_block(string $rawHeaders): array
{
    $headers = [];
    $lines = preg_split('/\r\n|\n|\r/', trim($rawHeaders)) ?: [];
    foreach ($lines as $line) {
        if (!is_string($line) || trim($line) === '' || !str_contains($line, ':')) {
            continue;
        }
        [$name, $value] = explode(':', $line, 2);
        $key = strtolower(trim((string) $name));
        if ($key === '') {
            continue;
        }
        $headers[$key] ??= [];
        $headers[$key][] = trim((string) $value);
    }
    return $headers;
}

function a11y_parse_headers_with_intermediate(string $rawHeaders): array
{
    $blocks = preg_split('/\r\n\r\n|\n\n|\r\r/', trim($rawHeaders)) ?: [];
    $parsed = [];
    foreach ($blocks as $block) {
        if (!is_string($block) || !str_contains($block, ':')) {
            continue;
        }
        $lines = preg_split('/\r\n|\n|\r/', trim($block)) ?: [];
        if (count($lines) === 0) {
            continue;
        }
        $statusLine = (string) ($lines[0] ?? '');
        $headers = a11y_parse_header_block($block);
        $parsed[] = [
            'status_line' => $statusLine,
            'headers' => $headers,
        ];
    }
    return $parsed;
}

function a11y_resolve_url(string $baseUrl, string $target): ?string
{
    $target = trim($target);
    if ($target === '') {
        return null;
    }
    if (preg_match('/^https?:\/\//i', $target)) {
        return $target;
    }
    if (str_starts_with($target, '//')) {
        $scheme = (string) parse_url($baseUrl, PHP_URL_SCHEME);
        if ($scheme === '') {
            return null;
        }
        return $scheme . ':' . $target;
    }

    $base = parse_url($baseUrl);
    if (!is_array($base)) {
        return null;
    }
    $scheme = strtolower((string) ($base['scheme'] ?? ''));
    $host = (string) ($base['host'] ?? '');
    if ($scheme === '' || $host === '') {
        return null;
    }
    $port = isset($base['port']) ? ':' . (int) $base['port'] : '';

    if (str_starts_with($target, '/')) {
        return $scheme . '://' . $host . $port . $target;
    }

    $basePath = (string) ($base['path'] ?? '/');
    $dir = preg_replace('~/[^/]*$~', '/', $basePath);
    if (!is_string($dir) || $dir === '') {
        $dir = '/';
    }
    $path = $dir . $target;

    $segments = explode('/', $path);
    $resolved = [];
    foreach ($segments as $segment) {
        if ($segment === '' || $segment === '.') {
            continue;
        }
        if ($segment === '..') {
            array_pop($resolved);
            continue;
        }
        $resolved[] = $segment;
    }
    return $scheme . '://' . $host . $port . '/' . implode('/', $resolved);
}

function a11y_fetch_once(string $url, int $timeout): array
{
    $parsed = parse_url($url);
    if (!is_array($parsed)) {
        return ['ok' => false, 'error' => 'URL invalide.'];
    }
    $host = strtolower((string) ($parsed['host'] ?? ''));
    $scheme = strtolower((string) ($parsed['scheme'] ?? 'https'));
    if ($host === '' || !in_array($scheme, ['http', 'https'], true)) {
        return ['ok' => false, 'error' => 'URL invalide.'];
    }
    $port = isset($parsed['port']) ? (int) $parsed['port'] : ($scheme === 'http' ? 80 : 443);
    if ($port < 1 || $port > 65535) {
        return ['ok' => false, 'error' => 'Port invalide.'];
    }

    $resolveError = '';
    $resolvedIp = resolve_public_ip_for_host($host, $resolveError);
    if (!is_string($resolvedIp) || $resolvedIp === '') {
        return ['ok' => false, 'error' => $resolveError !== '' ? $resolveError : 'Resolution DNS invalide.'];
    }

    $ch = curl_init($url);
    if ($ch === false) {
        return ['ok' => false, 'error' => 'Impossible d initialiser cURL.'];
    }

    $curlOptions = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 0,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_USERAGENT => 'SEO-Sitemap-Tool-A11yAudit/1.0',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
        CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $resolvedIp],
        CURLOPT_HTTPHEADER => [
            'Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
            'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
        ],
    ];
    if (defined('CURLOPT_PROTOCOLS')) {
        $curlOptions[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
    }
    if (defined('CURLOPT_REDIR_PROTOCOLS')) {
        $curlOptions[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
    }
    curl_setopt_array($ch, $curlOptions);

    $raw = curl_exec($ch);
    $errno = curl_errno($ch);
    $error = curl_error($ch);
    $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $totalTime = (float) curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    $contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);

    if (!is_string($raw) || $errno !== 0) {
        return [
            'ok' => false,
            'error' => $error !== '' ? $error : 'Erreur reseau lors du fetch de l URL.',
        ];
    }

    $headerChunk = substr($raw, 0, max(0, $headerSize));
    $body = (string) substr($raw, max(0, $headerSize));
    if (!is_string($headerChunk)) {
        return ['ok' => false, 'error' => 'Reponse HTTP invalide.'];
    }

    $headerBlocks = a11y_parse_headers_with_intermediate($headerChunk);
    $lastHeaderBlock = end($headerBlocks);
    $headers = is_array($lastHeaderBlock['headers'] ?? null) ? $lastHeaderBlock['headers'] : [];

    $flatHeaders = [];
    foreach ($headers as $name => $values) {
        $flatHeaders[$name] = is_array($values) ? implode(', ', $values) : (string) $values;
    }

    return [
        'ok' => true,
        'status_code' => $statusCode,
        'response_time_ms' => (int) round($totalTime * 1000),
        'content_type' => $contentType,
        'headers' => $flatHeaders,
        'body' => $body,
        'location' => (string) ($flatHeaders['location'] ?? ''),
    ];
}

function a11y_fetch_with_redirects(string $url, int $timeout, int $maxRedirects): array
{
    $currentUrl = $url;
    $redirectCount = 0;
    $visited = [];
    $chain = [];

    while (true) {
        if (isset($visited[$currentUrl])) {
            return ['ok' => false, 'error' => 'Boucle de redirection detectee.', 'redirect_chain' => $chain];
        }
        $visited[$currentUrl] = true;

        $validationError = '';
        if (!validate_public_url($currentUrl, $validationError)) {
            return ['ok' => false, 'error' => $validationError, 'redirect_chain' => $chain];
        }

        $fetch = a11y_fetch_once($currentUrl, $timeout);
        if (empty($fetch['ok'])) {
            return ['ok' => false, 'error' => (string) ($fetch['error'] ?? 'Erreur fetch URL.'), 'redirect_chain' => $chain];
        }

        $statusCode = (int) ($fetch['status_code'] ?? 0);
        $location = trim((string) ($fetch['location'] ?? ''));
        $isRedirect = in_array($statusCode, [301, 302, 303, 307, 308], true);

        $chain[] = [
            'url' => $currentUrl,
            'status' => $statusCode,
            'location' => $location,
            'https' => strtolower((string) parse_url($currentUrl, PHP_URL_SCHEME)) === 'https',
        ];

        if ($isRedirect && $location !== '' && $redirectCount < $maxRedirects) {
            $nextUrl = a11y_resolve_url($currentUrl, $location);
            if (!is_string($nextUrl) || $nextUrl === '') {
                return ['ok' => false, 'error' => 'URL de redirection invalide.', 'redirect_chain' => $chain];
            }
            $validationError = '';
            if (!validate_public_url($nextUrl, $validationError)) {
                return ['ok' => false, 'error' => 'Redirection bloquee: ' . $validationError, 'redirect_chain' => $chain];
            }
            $currentUrl = $nextUrl;
            $redirectCount++;
            continue;
        }

        if ($isRedirect && $location !== '' && $redirectCount >= $maxRedirects) {
            return ['ok' => false, 'error' => 'Trop de redirections.', 'redirect_chain' => $chain];
        }

        return [
            'ok' => true,
            'url' => $url,
            'final_url' => $currentUrl,
            'redirect_count' => $redirectCount,
            'redirect_chain' => $chain,
            'status_code' => $statusCode,
            'response_time_ms' => (int) ($fetch['response_time_ms'] ?? 0),
            'content_type' => (string) ($fetch['content_type'] ?? ''),
            'headers' => is_array($fetch['headers'] ?? null) ? $fetch['headers'] : [],
            'body' => (string) ($fetch['body'] ?? ''),
        ];
    }
}

function a11y_xpath_literal(string $value): string
{
    if (!str_contains($value, "'")) {
        return "'" . $value . "'";
    }
    if (!str_contains($value, '"')) {
        return '"' . $value . '"';
    }
    $parts = explode("'", $value);
    $escaped = [];
    foreach ($parts as $i => $part) {
        if ($part !== '') {
            $escaped[] = "'" . $part . "'";
        }
        if ($i < count($parts) - 1) {
            $escaped[] = '"\'"';
        }
    }
    return 'concat(' . implode(',', $escaped) . ')';
}

function a11y_dom_first_attr(DOMXPath $xpath, string $query, string $attribute): string
{
    $nodes = $xpath->query($query);
    if (!($nodes instanceof DOMNodeList) || $nodes->length === 0) {
        return '';
    }
    $node = $nodes->item(0);
    if (!($node instanceof DOMElement)) {
        return '';
    }
    return trim((string) $node->getAttribute($attribute));
}

function a11y_node_accessible_name(?DOMNode $node): string
{
    if (!($node instanceof DOMElement)) {
        return '';
    }
    $ariaLabel = trim((string) $node->getAttribute('aria-label'));
    if ($ariaLabel !== '') {
        return $ariaLabel;
    }
    $ariaLabelledBy = trim((string) $node->getAttribute('aria-labelledby'));
    if ($ariaLabelledBy !== '') {
        return $ariaLabelledBy;
    }
    $title = trim((string) $node->getAttribute('title'));
    if ($title !== '') {
        return $title;
    }
    $text = trim((string) $node->textContent);
    if ($text !== '') {
        return $text;
    }
    $value = trim((string) $node->getAttribute('value'));
    if ($value !== '') {
        return $value;
    }
    $alt = trim((string) $node->getAttribute('alt'));
    if ($alt !== '') {
        return $alt;
    }
    return '';
}

function a11y_is_control_labeled(DOMElement $control, DOMXPath $xpath): bool
{
    $ariaLabel = trim((string) $control->getAttribute('aria-label'));
    $ariaLabelledBy = trim((string) $control->getAttribute('aria-labelledby'));
    $title = trim((string) $control->getAttribute('title'));
    if ($ariaLabel !== '' || $ariaLabelledBy !== '' || $title !== '') {
        return true;
    }

    $id = trim((string) $control->getAttribute('id'));
    if ($id !== '') {
        $escapedId = str_replace('"', '\"', $id);
        $labelByFor = $xpath->query('//label[@for="' . $escapedId . '"]');
        if ($labelByFor instanceof DOMNodeList && $labelByFor->length > 0) {
            return true;
        }
    }

    $parent = $control->parentNode;
    while ($parent instanceof DOMElement) {
        if (strtolower($parent->tagName) === 'label') {
            return true;
        }
        $parent = $parent->parentNode;
    }
    return false;
}

function a11y_has_accessibility_named_image(DOMElement $link, DOMXPath $xpath): bool
{
    $images = $xpath->query('.//img', $link);
    if (!($images instanceof DOMNodeList)) {
        return false;
    }
    foreach ($images as $img) {
        if (!($img instanceof DOMElement)) {
            continue;
        }
        $alt = trim((string) $img->getAttribute('alt'));
        if ($alt !== '') {
            return true;
        }
    }
    return false;
}

function a11y_parse_html_signals(string $html, string $finalUrl): array
{
    $empty = [
        'html_lang' => '',
        'title' => '',
        'viewport_present' => false,
        'main_landmark' => false,
        'skip_link' => false,
        'image_total' => 0,
        'image_missing_alt' => 0,
        'image_empty_alt' => 0,
        'form_control_total' => 0,
        'unlabeled_form_controls' => 0,
        'button_total' => 0,
        'unnamed_buttons' => 0,
        'link_total' => 0,
        'unnamed_links' => 0,
        'iframe_total' => 0,
        'iframe_missing_title' => 0,
        'has_accessibility_page' => false,
        'has_accessibility_statement' => false,
        'has_multiyear_schema' => false,
        'has_action_plan' => false,
        'has_status_mention' => false,
        // RGAA 5 / WCAG 2.2 signals
        'focus_outline_killed' => false,
        'focus_visible_override' => false,
        'small_target_total' => 0,
        'small_target_examples' => [],
        'personal_input_total' => 0,
        'personal_input_missing_autocomplete' => 0,
        'has_captcha_widget' => false,
        'captcha_kinds' => [],
        'draggable_total' => 0,
        'has_help_link' => false,
        'inputs_text_should_be_typed_total' => 0,
        'inputs_text_should_be_typed_examples' => [],
        'has_header_landmark' => false,
        'has_nav_landmark' => false,
        'has_footer_landmark' => false,
        'video_total' => 0,
        'video_missing_captions' => 0,
        'autoplay_media_total' => 0,
        'audio_total' => 0,
        'audio_missing_transcript_hint' => 0,
        'doctype_html5' => false,
        'charset_declared' => false,
        'viewport_blocks_zoom' => false,
        'heading_skip_levels' => 0,
        'h1_count' => 0,
        'tables_total' => 0,
        'tables_missing_caption' => 0,
        'tables_missing_th' => 0,
        'fieldset_grouped_inputs_total' => 0,
        'fieldset_missing_legend' => 0,
        'lang_changes_inline_total' => 0,
    ];

    if (!class_exists('DOMDocument')) {
        return $empty;
    }
    if (trim($html) === '') {
        return $empty;
    }

    // Doctype detection (RGAA 8.1) — must happen before DOMDocument strips it.
    $doctypeHtml5 = (bool) preg_match('/<!doctype\s+html\s*>/i', substr($html, 0, 200));
    // Charset declared (RGAA 8.5) — meta charset or http-equiv.
    $charsetDeclared = (bool) preg_match('/<meta[^>]+charset\s*=\s*["\']?[a-z0-9_-]+/i', $html);

    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    $loaded = @$dom->loadHTML('<?xml encoding="utf-8" ?>' . $html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
    if ($loaded === false) {
        return $empty;
    }

    $xpath = new DOMXPath($dom);
    $htmlLang = trim((string) a11y_dom_first_attr($xpath, '//html', 'lang'));
    $title = trim((string) $dom->getElementsByTagName('title')->item(0)?->textContent);
    $viewportContent = a11y_dom_first_attr(
        $xpath,
        '//meta[translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="viewport"]',
        'content'
    );
    $viewportPresent = $viewportContent !== '';
    $viewportLow = strtolower(str_replace(' ', '', $viewportContent));
    $viewportBlocksZoom = (
        str_contains($viewportLow, 'user-scalable=no')
        || str_contains($viewportLow, 'user-scalable=0')
        || preg_match('/maximum-scale=(?:1(?!\d)|0?\.\d+)/', $viewportLow)
    ) ? true : false;

    $mainLandmark = false;
    $mainNodes = $xpath->query('//main | //*[@role="main"]');
    if ($mainNodes instanceof DOMNodeList && $mainNodes->length > 0) {
        $mainLandmark = true;
    }

    $skipLink = false;
    $skipNodes = $xpath->query('//a[@href]');
    if ($skipNodes instanceof DOMNodeList) {
        foreach ($skipNodes as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $href = trim((string) $node->getAttribute('href'));
            if (!str_starts_with($href, '#')) {
                continue;
            }
            $name = a11y_to_lower(a11y_node_accessible_name($node));
            if (str_contains($name, 'aller au contenu') || str_contains($name, 'contenu principal') || str_contains($name, 'skip to content')) {
                $skipLink = true;
                break;
            }
        }
    }

    $imageTotal = 0;
    $imageMissingAlt = 0;
    $imageEmptyAlt = 0;
    $images = $xpath->query('//img');
    if ($images instanceof DOMNodeList) {
        $imageTotal = $images->length;
        foreach ($images as $img) {
            if (!($img instanceof DOMElement)) {
                continue;
            }
            if (!$img->hasAttribute('alt')) {
                $imageMissingAlt++;
                continue;
            }
            if (trim((string) $img->getAttribute('alt')) === '') {
                $imageEmptyAlt++;
            }
        }
    }

    $formControlTotal = 0;
    $unlabeledFormControls = 0;
    $formControls = $xpath->query('//input[not(translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="hidden")] | //select | //textarea');
    if ($formControls instanceof DOMNodeList) {
        $formControlTotal = $formControls->length;
        foreach ($formControls as $control) {
            if (!($control instanceof DOMElement)) {
                continue;
            }
            if (!a11y_is_control_labeled($control, $xpath)) {
                $unlabeledFormControls++;
            }
        }
    }

    $buttonTotal = 0;
    $unnamedButtons = 0;
    $buttonNodes = $xpath->query('//button | //input[translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="submit" or translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="button" or translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="reset" or translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="image"]');
    if ($buttonNodes instanceof DOMNodeList) {
        $buttonTotal = $buttonNodes->length;
        foreach ($buttonNodes as $button) {
            $name = a11y_node_accessible_name($button);
            if (trim($name) === '') {
                $unnamedButtons++;
            }
        }
    }

    $linkTotal = 0;
    $unnamedLinks = 0;
    $linkNodes = $xpath->query('//a[@href]');
    if ($linkNodes instanceof DOMNodeList) {
        foreach ($linkNodes as $link) {
            if (!($link instanceof DOMElement)) {
                continue;
            }
            $href = trim((string) $link->getAttribute('href'));
            if ($href === '' || str_starts_with(strtolower($href), 'javascript:')) {
                continue;
            }
            $linkTotal++;
            $name = trim(a11y_node_accessible_name($link));
            if ($name === '' && !a11y_has_accessibility_named_image($link, $xpath)) {
                $unnamedLinks++;
            }
        }
    }

    $iframeTotal = 0;
    $iframeMissingTitle = 0;
    $iframeNodes = $xpath->query('//iframe');
    if ($iframeNodes instanceof DOMNodeList) {
        $iframeTotal = $iframeNodes->length;
        foreach ($iframeNodes as $frame) {
            if (!($frame instanceof DOMElement)) {
                continue;
            }
            $titleAttr = trim((string) $frame->getAttribute('title'));
            if ($titleAttr === '') {
                $iframeMissingTitle++;
            }
        }
    }

    $hasAccessibilityPage = false;
    $hasAccessibilityStatement = false;
    $hasMultiyearSchema = false;
    $hasActionPlan = false;

    if ($linkNodes instanceof DOMNodeList) {
        foreach ($linkNodes as $link) {
            if (!($link instanceof DOMElement)) {
                continue;
            }
            $href = a11y_to_lower(trim((string) $link->getAttribute('href')));
            $text = a11y_to_lower(trim((string) $link->textContent));
            $combined = $href . ' ' . $text;

            if (!$hasAccessibilityPage && (str_contains($combined, 'accessibilite') || str_contains($combined, 'accessibilité'))) {
                $hasAccessibilityPage = true;
            }
            if (!$hasAccessibilityStatement && (str_contains($combined, 'declaration-accessibilite') || str_contains($combined, 'declaration d accessibilite') || str_contains($combined, 'déclaration d’accessibilité') || str_contains($combined, 'déclaration d\'accessibilité'))) {
                $hasAccessibilityStatement = true;
            }
            if (!$hasMultiyearSchema && (str_contains($combined, 'schema-pluriannuel') || str_contains($combined, 'schéma pluriannuel') || str_contains($combined, 'schema pluriannuel'))) {
                $hasMultiyearSchema = true;
            }
            if (!$hasActionPlan && (str_contains($combined, 'plan-action') || str_contains($combined, 'plan d action') || str_contains($combined, 'plan d’actions') || str_contains($combined, 'plan d\'actions'))) {
                $hasActionPlan = true;
            }
        }
    }

    $pageText = a11y_to_lower(trim((string) preg_replace('/\s+/u', ' ', strip_tags($html))));
    $hasStatusMention = (bool) preg_match('/accessibilit(?:e|é)\s*:\s*(totalement|partiellement|non)\s+conforme/u', $pageText);

    // ---- RGAA 5 / WCAG 2.2 signals ---------------------------------------

    // Focus visible (SC 2.4.13): scan inline <style> blocks + style attributes for outline:0/none.
    $focusOutlineKilled = false;
    $focusVisibleOverride = false;
    $styleNodes = $xpath->query('//style');
    $cssBuffer = '';
    if ($styleNodes instanceof DOMNodeList) {
        foreach ($styleNodes as $node) {
            $cssBuffer .= ' ' . (string) $node->textContent;
        }
    }
    // Add inline style attributes too (rare but possible)
    $inlineStyles = $xpath->query('//*[@style]');
    if ($inlineStyles instanceof DOMNodeList) {
        foreach ($inlineStyles as $node) {
            if ($node instanceof DOMElement) {
                $cssBuffer .= ' ' . (string) $node->getAttribute('style');
            }
        }
    }
    $cssLower = strtolower($cssBuffer);
    if (preg_match('/(?::focus|:focus-within|button|a|input|select|textarea|\*)\s*[^{]*\{[^}]*outline\s*:\s*(?:none|0(?!\.)|0px)\b[^}]*\}/i', $cssBuffer)) {
        $focusOutlineKilled = true;
    }
    if (preg_match('/:focus-visible[^{]*\{[^}]*outline\s*:\s*(?!none|0(?!\.)|0px)/i', $cssBuffer)) {
        $focusVisibleOverride = true;
    }

    // Target size (SC 2.5.8): interactive elements with explicit small dimensions.
    $smallTargetTotal = 0;
    $smallTargetExamples = [];
    $sizeRe = '/(?:^|;|\s)(width|height)\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*(px|rem|em|pt)?\b/i';
    $interactiveNodes = $xpath->query('//button | //a[@href] | //input[not(translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="hidden")] | //select | //textarea | //*[@role="button" or @role="link" or @role="checkbox" or @role="radio" or @role="tab"]');
    if ($interactiveNodes instanceof DOMNodeList) {
        foreach ($interactiveNodes as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $w = null;
            $h = null;
            // HTML width/height attributes (in px by spec).
            if ($node->hasAttribute('width')) {
                $val = trim((string) $node->getAttribute('width'));
                if (is_numeric($val)) {
                    $w = (float) $val;
                }
            }
            if ($node->hasAttribute('height')) {
                $val = trim((string) $node->getAttribute('height'));
                if (is_numeric($val)) {
                    $h = (float) $val;
                }
            }
            // Inline style.
            if ($node->hasAttribute('style')) {
                $style = (string) $node->getAttribute('style');
                if (preg_match_all($sizeRe, $style, $matches, PREG_SET_ORDER)) {
                    foreach ($matches as $m) {
                        $prop = strtolower($m[1]);
                        $num = (float) $m[2];
                        $unit = strtolower($m[3] ?? 'px');
                        $px = $unit === 'px' ? $num : ($unit === 'pt' ? $num * 1.333 : $num * 16); // approx rem/em as 16px
                        if ($prop === 'width') {
                            $w = $px;
                        } elseif ($prop === 'height') {
                            $h = $px;
                        }
                    }
                }
            }
            if ($w !== null && $h !== null && $w > 0 && $h > 0 && ($w < 24 || $h < 24)) {
                $smallTargetTotal++;
                if (count($smallTargetExamples) < 5) {
                    $smallTargetExamples[] = strtolower($node->nodeName) . ' ' . (int) round($w) . 'x' . (int) round($h);
                }
            }
        }
    }

    // Autocomplete on personal info fields (SC 1.3.5 / RGAA 11.13).
    $personalInputTotal = 0;
    $personalInputMissingAutocomplete = 0;
    $personalNamePattern = '/(email|courriel|name|nom|prenom|first.?name|last.?name|family.?name|phone|tel|telephone|address|adresse|street|street.?address|postal|zip|cp|city|ville|country|pays|birthday|birthdate|date.?of.?birth|cc-|credit.?card|card.?number|cvc|cvv)/i';
    $personalNodes = $xpath->query('//input[not(translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="hidden") and not(translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="submit") and not(translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="button") and not(translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="reset") and not(translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="checkbox") and not(translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="radio")]');
    if ($personalNodes instanceof DOMNodeList) {
        foreach ($personalNodes as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $type = strtolower(trim((string) $node->getAttribute('type')));
            $name = trim((string) $node->getAttribute('name'));
            $id = trim((string) $node->getAttribute('id'));
            $autoc = trim((string) $node->getAttribute('autocomplete'));
            $haystack = $type . ' ' . $name . ' ' . $id;

            $isPersonal = ($type === 'email' || $type === 'tel' || preg_match($personalNamePattern, $haystack));
            if (!$isPersonal) {
                continue;
            }
            $personalInputTotal++;
            if ($autoc === '' || strtolower($autoc) === 'off') {
                $personalInputMissingAutocomplete++;
            }
        }
    }

    // Captcha widget detection (SC 3.3.8 / accessible authentication).
    $hasCaptchaWidget = false;
    $captchaKinds = [];
    $htmlLowerSnippet = strtolower($html);
    if (str_contains($htmlLowerSnippet, 'g-recaptcha') || str_contains($htmlLowerSnippet, 'recaptcha/api') || str_contains($htmlLowerSnippet, 'google.com/recaptcha')) {
        $hasCaptchaWidget = true;
        $captchaKinds[] = 'recaptcha';
    }
    if (str_contains($htmlLowerSnippet, 'h-captcha') || str_contains($htmlLowerSnippet, 'hcaptcha.com')) {
        $hasCaptchaWidget = true;
        $captchaKinds[] = 'hcaptcha';
    }
    if (str_contains($htmlLowerSnippet, 'cf-turnstile') || str_contains($htmlLowerSnippet, 'challenges.cloudflare.com/turnstile')) {
        $hasCaptchaWidget = true;
        $captchaKinds[] = 'turnstile';
    }
    if (str_contains($htmlLowerSnippet, 'friendlycaptcha')) {
        $hasCaptchaWidget = true;
        $captchaKinds[] = 'friendlycaptcha';
    }

    // Drag-and-drop (SC 2.5.7).
    $draggableTotal = 0;
    $draggableNodes = $xpath->query('//*[@draggable="true"]');
    if ($draggableNodes instanceof DOMNodeList) {
        $draggableTotal = $draggableNodes->length;
    }

    // Modern input types (HTML5 semantic inputs improve mobile keyboards / a11y).
    $inputsTextShouldBeTypedTotal = 0;
    $inputsTextShouldBeTypedExamples = [];
    $textInputs = $xpath->query('//input[not(@type) or translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="text"]');
    if ($textInputs instanceof DOMNodeList) {
        foreach ($textInputs as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $name = strtolower(trim((string) $node->getAttribute('name')));
            $id = strtolower(trim((string) $node->getAttribute('id')));
            $hint = $name . ' ' . $id;
            $expected = '';
            if (preg_match('/email|courriel|mail/i', $hint)) {
                $expected = 'email';
            } elseif (preg_match('/phone|tel(?!ler)|mobile|telephone/i', $hint)) {
                $expected = 'tel';
            } elseif (preg_match('/url|website|site_web/i', $hint)) {
                $expected = 'url';
            } elseif (preg_match('/birth|date.?(de.?)?naiss|date_of_birth|dob/i', $hint)) {
                $expected = 'date';
            } elseif (preg_match('/(?:^|_)number|montant|amount|quantity|qty/i', $hint)) {
                $expected = 'number';
            }
            if ($expected !== '') {
                $inputsTextShouldBeTypedTotal++;
                if (count($inputsTextShouldBeTypedExamples) < 5) {
                    $inputsTextShouldBeTypedExamples[] = ($name !== '' ? $name : ($id !== '' ? '#' . $id : 'input')) . ' -> ' . $expected;
                }
            }
        }
    }

    // Landmark structure completeness (WCAG 1.3.1 / RGAA 9.1).
    $hasHeaderLandmark = false;
    $hasNavLandmark = false;
    $hasFooterLandmark = false;
    if ($xpath->query('//header | //*[@role="banner"]')->length > 0) {
        $hasHeaderLandmark = true;
    }
    if ($xpath->query('//nav | //*[@role="navigation"]')->length > 0) {
        $hasNavLandmark = true;
    }
    if ($xpath->query('//footer | //*[@role="contentinfo"]')->length > 0) {
        $hasFooterLandmark = true;
    }

    // Video captions (WCAG 1.2.2).
    $videoTotal = 0;
    $videoMissingCaptions = 0;
    $videoNodes = $xpath->query('//video');
    if ($videoNodes instanceof DOMNodeList) {
        $videoTotal = $videoNodes->length;
        foreach ($videoNodes as $video) {
            if (!($video instanceof DOMElement)) {
                continue;
            }
            $hasCaptions = false;
            $tracks = $video->getElementsByTagName('track');
            foreach ($tracks as $track) {
                if (!($track instanceof DOMElement)) {
                    continue;
                }
                $kind = strtolower(trim((string) $track->getAttribute('kind')));
                if (in_array($kind, ['captions', 'subtitles'], true)) {
                    $hasCaptions = true;
                    break;
                }
            }
            if (!$hasCaptions) {
                $videoMissingCaptions++;
            }
        }
    }

    // Heading hierarchy (RGAA 9.1 / WCAG 1.3.1).
    $headingSkipLevels = 0;
    $h1Count = 0;
    $headingNodes = $xpath->query('//h1|//h2|//h3|//h4|//h5|//h6');
    if ($headingNodes instanceof DOMNodeList) {
        $previousLevel = 0;
        foreach ($headingNodes as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $level = (int) substr(strtolower($node->nodeName), 1);
            if ($level === 1) {
                $h1Count++;
            }
            if ($previousLevel > 0 && $level > $previousLevel + 1) {
                $headingSkipLevels++;
            }
            $previousLevel = $level;
        }
    }

    // Tables (RGAA 5.1, 5.4, 5.6, 5.7) — caption + th present.
    $tablesTotal = 0;
    $tablesMissingCaption = 0;
    $tablesMissingTh = 0;
    $tableNodes = $xpath->query('//table');
    if ($tableNodes instanceof DOMNodeList) {
        foreach ($tableNodes as $table) {
            if (!($table instanceof DOMElement)) {
                continue;
            }
            // Skip layout tables (role="presentation" / "none").
            $role = strtolower(trim((string) $table->getAttribute('role')));
            if (in_array($role, ['presentation', 'none'], true)) {
                continue;
            }
            $tablesTotal++;
            $hasCaption = $table->getElementsByTagName('caption')->length > 0;
            $hasTh = $table->getElementsByTagName('th')->length > 0;
            if (!$hasCaption) {
                $tablesMissingCaption++;
            }
            if (!$hasTh) {
                $tablesMissingTh++;
            }
        }
    }

    // Fieldset/legend on grouped inputs (RGAA 11.5).
    $fieldsetGroupedInputsTotal = 0;
    $fieldsetMissingLegend = 0;
    $radioCheckboxNodes = $xpath->query('//input[translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="radio" or translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="checkbox"]');
    $groupNames = [];
    if ($radioCheckboxNodes instanceof DOMNodeList) {
        foreach ($radioCheckboxNodes as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $name = trim((string) $node->getAttribute('name'));
            if ($name === '') {
                continue;
            }
            $groupNames[$name] = ($groupNames[$name] ?? 0) + 1;
        }
    }
    foreach ($groupNames as $name => $count) {
        if ($count < 2) {
            continue;
        }
        $fieldsetGroupedInputsTotal++;
        $matchedInsideFieldset = false;
        $controls = $xpath->query('//input[(translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="radio" or translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="checkbox") and @name=' . a11y_xpath_literal($name) . ']');
        if ($controls instanceof DOMNodeList) {
            foreach ($controls as $ctrl) {
                if (!($ctrl instanceof DOMElement)) {
                    continue;
                }
                $parent = $ctrl->parentNode;
                while ($parent instanceof DOMElement) {
                    if (strtolower($parent->nodeName) === 'fieldset') {
                        $matchedInsideFieldset = $parent->getElementsByTagName('legend')->length > 0;
                        break 2;
                    }
                    $parent = $parent->parentNode;
                }
            }
        }
        if (!$matchedInsideFieldset) {
            $fieldsetMissingLegend++;
        }
    }

    // Autoplay media (WCAG 1.4.2 / RGAA 4.7).
    $autoplayMediaTotal = $xpath->query('//video[@autoplay]|//audio[@autoplay]')->length;

    // Inline lang changes (RGAA 8.7) — count <span lang> / [lang] inside body excluding html itself.
    $langChangesInlineTotal = $xpath->query('//body//*[@lang and not(self::html)]')->length;

    // Audio with transcript heuristic (WCAG 1.2.1).
    $audioTotal = 0;
    $audioMissingTranscriptHint = 0;
    $audioNodes = $xpath->query('//audio');
    if ($audioNodes instanceof DOMNodeList) {
        $audioTotal = $audioNodes->length;
        $pageTextLower = strtolower((string) preg_replace('/\s+/u', ' ', strip_tags($html)));
        $hasTranscriptHint = (
            str_contains($pageTextLower, 'transcript')
            || str_contains($pageTextLower, 'transcription')
            || str_contains($pageTextLower, 'verbatim')
        );
        $audioMissingTranscriptHint = $hasTranscriptHint ? 0 : $audioTotal;
    }

    // Consistent help (SC 3.2.6) — at minimum, surface a help/contact affordance.
    $hasHelpLink = false;
    if ($linkNodes instanceof DOMNodeList) {
        foreach ($linkNodes as $link) {
            if (!($link instanceof DOMElement)) {
                continue;
            }
            $hrefLow = a11y_to_lower((string) $link->getAttribute('href'));
            $textLow = a11y_to_lower((string) $link->textContent);
            $combined = $hrefLow . ' ' . $textLow;
            if (
                str_contains($combined, 'contact')
                || str_contains($combined, '/aide')
                || str_contains($combined, '/help')
                || str_contains($combined, '/support')
                || str_contains($combined, '/faq')
                || preg_match('/\b(aide|help|support|nous contacter|contactez)\b/u', $combined)
            ) {
                $hasHelpLink = true;
                break;
            }
        }
    }

    return [
        'html_lang' => $htmlLang,
        'title' => $title,
        'viewport_present' => $viewportPresent,
        'main_landmark' => $mainLandmark,
        'skip_link' => $skipLink,
        'image_total' => $imageTotal,
        'image_missing_alt' => $imageMissingAlt,
        'image_empty_alt' => $imageEmptyAlt,
        'form_control_total' => $formControlTotal,
        'unlabeled_form_controls' => $unlabeledFormControls,
        'button_total' => $buttonTotal,
        'unnamed_buttons' => $unnamedButtons,
        'link_total' => $linkTotal,
        'unnamed_links' => $unnamedLinks,
        'iframe_total' => $iframeTotal,
        'iframe_missing_title' => $iframeMissingTitle,
        'has_accessibility_page' => $hasAccessibilityPage,
        'has_accessibility_statement' => $hasAccessibilityStatement,
        'has_multiyear_schema' => $hasMultiyearSchema,
        'has_action_plan' => $hasActionPlan,
        'has_status_mention' => $hasStatusMention,
        'focus_outline_killed' => $focusOutlineKilled,
        'focus_visible_override' => $focusVisibleOverride,
        'small_target_total' => $smallTargetTotal,
        'small_target_examples' => $smallTargetExamples,
        'personal_input_total' => $personalInputTotal,
        'personal_input_missing_autocomplete' => $personalInputMissingAutocomplete,
        'has_captcha_widget' => $hasCaptchaWidget,
        'captcha_kinds' => array_values(array_unique($captchaKinds)),
        'draggable_total' => $draggableTotal,
        'has_help_link' => $hasHelpLink,
        'inputs_text_should_be_typed_total' => $inputsTextShouldBeTypedTotal,
        'inputs_text_should_be_typed_examples' => $inputsTextShouldBeTypedExamples,
        'has_header_landmark' => $hasHeaderLandmark,
        'has_nav_landmark' => $hasNavLandmark,
        'has_footer_landmark' => $hasFooterLandmark,
        'video_total' => $videoTotal,
        'video_missing_captions' => $videoMissingCaptions,
        'audio_total' => $audioTotal,
        'audio_missing_transcript_hint' => $audioMissingTranscriptHint,
        'autoplay_media_total' => $autoplayMediaTotal,
        'doctype_html5' => $doctypeHtml5,
        'charset_declared' => $charsetDeclared,
        'viewport_blocks_zoom' => $viewportBlocksZoom,
        'heading_skip_levels' => $headingSkipLevels,
        'h1_count' => $h1Count,
        'tables_total' => $tablesTotal,
        'tables_missing_caption' => $tablesMissingCaption,
        'tables_missing_th' => $tablesMissingTh,
        'fieldset_grouped_inputs_total' => $fieldsetGroupedInputsTotal,
        'fieldset_missing_legend' => $fieldsetMissingLegend,
        'lang_changes_inline_total' => $langChangesInlineTotal,
    ];
}

function a11y_add_check(array &$checks, string $key, string $status, string $value, bool $rgaa5Only = false): void
{
    $safe = strtolower(trim($status));
    if (!in_array($safe, ['pass', 'warn', 'fail'], true)) {
        $safe = 'warn';
    }
    $checks[] = [
        'key' => $key,
        'status' => $safe,
        'value' => $value,
        'rgaa5_only' => $rgaa5Only,
    ];
}

$fetch = a11y_fetch_with_redirects($url, $timeout, $maxRedirects);
if (empty($fetch['ok'])) {
    respond_json(['error' => (string) ($fetch['error'] ?? 'Erreur audit URL.')], 400);
}

$finalUrl = (string) ($fetch['final_url'] ?? $url);
$statusCode = (int) ($fetch['status_code'] ?? 0);
$responseMs = (int) ($fetch['response_time_ms'] ?? 0);
$contentType = (string) ($fetch['content_type'] ?? '');
$redirectCount = (int) ($fetch['redirect_count'] ?? 0);
$redirectChain = is_array($fetch['redirect_chain'] ?? null) ? $fetch['redirect_chain'] : [];
$html = (string) ($fetch['body'] ?? '');
$signals = a11y_parse_html_signals($html, $finalUrl);

$is2xx = $statusCode >= 200 && $statusCode < 300;
$langPresent = trim((string) ($signals['html_lang'] ?? '')) !== '';
$titlePresent = trim((string) ($signals['title'] ?? '')) !== '';
$viewportPresent = (bool) ($signals['viewport_present'] ?? false);
$mainLandmark = (bool) ($signals['main_landmark'] ?? false);
$skipLink = (bool) ($signals['skip_link'] ?? false);
$imageTotal = (int) ($signals['image_total'] ?? 0);
$imageMissingAlt = (int) ($signals['image_missing_alt'] ?? 0);
$formControlTotal = (int) ($signals['form_control_total'] ?? 0);
$unlabeledFormControls = (int) ($signals['unlabeled_form_controls'] ?? 0);
$buttonTotal = (int) ($signals['button_total'] ?? 0);
$unnamedButtons = (int) ($signals['unnamed_buttons'] ?? 0);
$linkTotal = (int) ($signals['link_total'] ?? 0);
$unnamedLinks = (int) ($signals['unnamed_links'] ?? 0);
$iframeTotal = (int) ($signals['iframe_total'] ?? 0);
$iframeMissingTitle = (int) ($signals['iframe_missing_title'] ?? 0);
$hasAccessibilityPage = (bool) ($signals['has_accessibility_page'] ?? false);
$hasAccessibilityStatement = (bool) ($signals['has_accessibility_statement'] ?? false);
$hasMultiyearSchema = (bool) ($signals['has_multiyear_schema'] ?? false);
$hasActionPlan = (bool) ($signals['has_action_plan'] ?? false);
$hasStatusMention = (bool) ($signals['has_status_mention'] ?? false);

// RGAA 5 / WCAG 2.2 signals
$focusOutlineKilled = (bool) ($signals['focus_outline_killed'] ?? false);
$focusVisibleOverride = (bool) ($signals['focus_visible_override'] ?? false);
$smallTargetTotal = (int) ($signals['small_target_total'] ?? 0);
$smallTargetExamples = is_array($signals['small_target_examples'] ?? null) ? $signals['small_target_examples'] : [];
$personalInputTotal = (int) ($signals['personal_input_total'] ?? 0);
$personalInputMissingAutocomplete = (int) ($signals['personal_input_missing_autocomplete'] ?? 0);
$hasCaptchaWidget = (bool) ($signals['has_captcha_widget'] ?? false);
$captchaKinds = is_array($signals['captcha_kinds'] ?? null) ? $signals['captcha_kinds'] : [];
$draggableTotal = (int) ($signals['draggable_total'] ?? 0);
$hasHelpLink = (bool) ($signals['has_help_link'] ?? false);
$inputsTextShouldBeTypedTotal = (int) ($signals['inputs_text_should_be_typed_total'] ?? 0);
$inputsTextShouldBeTypedExamples = is_array($signals['inputs_text_should_be_typed_examples'] ?? null) ? $signals['inputs_text_should_be_typed_examples'] : [];
$hasHeaderLandmark = (bool) ($signals['has_header_landmark'] ?? false);
$hasNavLandmark = (bool) ($signals['has_nav_landmark'] ?? false);
$hasFooterLandmark = (bool) ($signals['has_footer_landmark'] ?? false);
$videoTotal = (int) ($signals['video_total'] ?? 0);
$videoMissingCaptions = (int) ($signals['video_missing_captions'] ?? 0);
$audioTotal = (int) ($signals['audio_total'] ?? 0);
$audioMissingTranscriptHint = (int) ($signals['audio_missing_transcript_hint'] ?? 0);
$autoplayMediaTotal = (int) ($signals['autoplay_media_total'] ?? 0);
$doctypeHtml5 = (bool) ($signals['doctype_html5'] ?? false);
$charsetDeclared = (bool) ($signals['charset_declared'] ?? false);
$viewportBlocksZoom = (bool) ($signals['viewport_blocks_zoom'] ?? false);
$headingSkipLevels = (int) ($signals['heading_skip_levels'] ?? 0);
$h1Count = (int) ($signals['h1_count'] ?? 0);
$tablesTotal = (int) ($signals['tables_total'] ?? 0);
$tablesMissingCaption = (int) ($signals['tables_missing_caption'] ?? 0);
$tablesMissingTh = (int) ($signals['tables_missing_th'] ?? 0);
$fieldsetGroupedInputsTotal = (int) ($signals['fieldset_grouped_inputs_total'] ?? 0);
$fieldsetMissingLegend = (int) ($signals['fieldset_missing_legend'] ?? 0);
$langChangesInlineTotal = (int) ($signals['lang_changes_inline_total'] ?? 0);

$checks = [];
a11y_add_check($checks, 'a11y_http_status_2xx', $is2xx ? 'pass' : 'fail', (string) $statusCode);
a11y_add_check($checks, 'a11y_html_lang_present', $langPresent ? 'pass' : 'fail', $langPresent ? trim((string) $signals['html_lang']) : '-');
a11y_add_check($checks, 'a11y_title_present', $titlePresent ? 'pass' : 'fail', $titlePresent ? 'yes' : 'no');
a11y_add_check($checks, 'a11y_viewport_present', $viewportPresent ? 'pass' : 'warn', $viewportPresent ? 'yes' : 'no');
a11y_add_check($checks, 'a11y_main_landmark', $mainLandmark ? 'pass' : 'fail', $mainLandmark ? 'yes' : 'no');
a11y_add_check($checks, 'a11y_skip_link', $skipLink ? 'pass' : 'warn', $skipLink ? 'yes' : 'no');

if ($imageTotal <= 0) {
    a11y_add_check($checks, 'a11y_image_alt_coverage', 'pass', '0/0');
} else {
    $ratio = $imageMissingAlt / max(1, $imageTotal);
    $status = $imageMissingAlt === 0 ? 'pass' : ($ratio <= 0.1 ? 'warn' : 'fail');
    a11y_add_check($checks, 'a11y_image_alt_coverage', $status, $imageMissingAlt . '/' . $imageTotal);
}

if ($formControlTotal <= 0) {
    a11y_add_check($checks, 'a11y_form_labels', 'pass', '0/0');
} else {
    $ratio = $unlabeledFormControls / max(1, $formControlTotal);
    $status = $unlabeledFormControls === 0 ? 'pass' : ($ratio <= 0.1 ? 'warn' : 'fail');
    a11y_add_check($checks, 'a11y_form_labels', $status, $unlabeledFormControls . '/' . $formControlTotal);
}

if ($buttonTotal <= 0) {
    a11y_add_check($checks, 'a11y_button_names', 'pass', '0/0');
} else {
    $ratio = $unnamedButtons / max(1, $buttonTotal);
    $status = $unnamedButtons === 0 ? 'pass' : ($ratio <= 0.1 ? 'warn' : 'fail');
    a11y_add_check($checks, 'a11y_button_names', $status, $unnamedButtons . '/' . $buttonTotal);
}

if ($linkTotal <= 0) {
    a11y_add_check($checks, 'a11y_link_names', 'warn', '0/0');
} else {
    $ratio = $unnamedLinks / max(1, $linkTotal);
    $status = $unnamedLinks === 0 ? 'pass' : ($ratio <= 0.1 ? 'warn' : 'fail');
    a11y_add_check($checks, 'a11y_link_names', $status, $unnamedLinks . '/' . $linkTotal);
}

if ($iframeTotal <= 0) {
    a11y_add_check($checks, 'a11y_iframe_titles', 'pass', '0/0');
} else {
    $status = $iframeMissingTitle === 0 ? 'pass' : 'fail';
    a11y_add_check($checks, 'a11y_iframe_titles', $status, $iframeMissingTitle . '/' . $iframeTotal);
}

a11y_add_check($checks, 'a11y_accessibility_page', $hasAccessibilityPage ? 'pass' : 'warn', $hasAccessibilityPage ? 'yes' : 'no');
a11y_add_check($checks, 'a11y_accessibility_statement', $hasAccessibilityStatement ? 'pass' : 'warn', $hasAccessibilityStatement ? 'yes' : 'no');
a11y_add_check($checks, 'a11y_accessibility_multiyear', $hasMultiyearSchema ? 'pass' : 'warn', $hasMultiyearSchema ? 'yes' : 'no');
a11y_add_check($checks, 'a11y_accessibility_plan', $hasActionPlan ? 'pass' : 'warn', $hasActionPlan ? 'yes' : 'no');
a11y_add_check($checks, 'a11y_accessibility_status_mention', $hasStatusMention ? 'pass' : 'warn', $hasStatusMention ? 'yes' : 'no');

// ---- Common RGAA 4 + 5 structural checks (always run) ----

// RGAA 8.1 — Doctype HTML5
a11y_add_check($checks, 'a11y_doctype_html5', $doctypeHtml5 ? 'pass' : 'warn', $doctypeHtml5 ? '<!doctype html>' : 'manquant');

// RGAA 8.5 — Charset declared
a11y_add_check($checks, 'a11y_charset_declared', $charsetDeclared ? 'pass' : 'warn', $charsetDeclared ? 'meta charset detecte' : 'absent');

// RGAA 13.8 / WCAG 1.4.4 — viewport must not block zoom
if ($viewportBlocksZoom) {
    a11y_add_check($checks, 'a11y_viewport_zoom_allowed', 'fail', 'user-scalable=no / maximum-scale<=1');
} else {
    a11y_add_check($checks, 'a11y_viewport_zoom_allowed', 'pass', 'zoom autorise');
}

// RGAA 9.1 / WCAG 1.3.1 — heading hierarchy + single H1
if ($h1Count === 0) {
    a11y_add_check($checks, 'a11y_heading_hierarchy', 'fail', 'aucun H1');
} elseif ($h1Count > 1) {
    a11y_add_check($checks, 'a11y_heading_hierarchy', 'warn', $h1Count . ' H1');
} elseif ($headingSkipLevels > 0) {
    a11y_add_check($checks, 'a11y_heading_hierarchy', 'warn', $headingSkipLevels . ' saut(s) de niveau');
} else {
    a11y_add_check($checks, 'a11y_heading_hierarchy', 'pass', '1 H1, hierarchie continue');
}

// RGAA 5 (Tableaux) — caption + th
if ($tablesTotal === 0) {
    a11y_add_check($checks, 'a11y_tables_accessible', 'pass', '0 tableau de donnees');
} else {
    $issues = [];
    if ($tablesMissingCaption > 0) $issues[] = $tablesMissingCaption . ' sans caption';
    if ($tablesMissingTh > 0) $issues[] = $tablesMissingTh . ' sans th';
    if (count($issues) === 0) {
        a11y_add_check($checks, 'a11y_tables_accessible', 'pass', $tablesTotal . ' tableau(x) ok');
    } else {
        $status = $tablesMissingTh > 0 ? 'fail' : 'warn';
        a11y_add_check($checks, 'a11y_tables_accessible', $status, implode(', ', $issues) . ' / ' . $tablesTotal);
    }
}

// RGAA 11.5 — fieldset/legend on grouped inputs
if ($fieldsetGroupedInputsTotal === 0) {
    a11y_add_check($checks, 'a11y_fieldset_legend', 'pass', 'aucun groupe radio/checkbox');
} else {
    $status = $fieldsetMissingLegend === 0 ? 'pass' : ($fieldsetMissingLegend === $fieldsetGroupedInputsTotal ? 'fail' : 'warn');
    a11y_add_check($checks, 'a11y_fieldset_legend', $status, $fieldsetMissingLegend . '/' . $fieldsetGroupedInputsTotal . ' groupe(s) sans fieldset+legend');
}

// RGAA 4.7 / WCAG 1.4.2 — autoplay media
a11y_add_check($checks, 'a11y_no_autoplay_media', $autoplayMediaTotal === 0 ? 'pass' : 'fail', $autoplayMediaTotal === 0 ? 'aucun' : $autoplayMediaTotal . ' element(s) autoplay');

// ---- RGAA 5 / WCAG 2.2 specific checks (only run when standard = rgaa5) ----
if ($referenceStandard === 'rgaa5') {
    // SC 2.4.13 — Focus appearance
    if ($focusOutlineKilled && !$focusVisibleOverride) {
        a11y_add_check($checks, 'a11y_rgaa5_focus_visible', 'fail', 'outline:none sans :focus-visible', true);
    } elseif ($focusOutlineKilled && $focusVisibleOverride) {
        a11y_add_check($checks, 'a11y_rgaa5_focus_visible', 'warn', 'outline retire mais :focus-visible present', true);
    } else {
        a11y_add_check($checks, 'a11y_rgaa5_focus_visible', 'pass', 'outline preserve', true);
    }

    // SC 2.5.8 — Target size minimum (24x24)
    if ($smallTargetTotal === 0) {
        a11y_add_check($checks, 'a11y_rgaa5_target_size', 'pass', '0', true);
    } else {
        $sample = count($smallTargetExamples) > 0 ? ' (' . implode(', ', $smallTargetExamples) . ')' : '';
        $status = $smallTargetTotal >= 5 ? 'fail' : 'warn';
        a11y_add_check($checks, 'a11y_rgaa5_target_size', $status, $smallTargetTotal . $sample, true);
    }

    // SC 1.3.5 — Autocomplete on personal info fields
    if ($personalInputTotal === 0) {
        a11y_add_check($checks, 'a11y_rgaa5_autocomplete_personal', 'pass', '0/0', true);
    } else {
        $ratio = $personalInputMissingAutocomplete / max(1, $personalInputTotal);
        $status = $personalInputMissingAutocomplete === 0 ? 'pass' : ($ratio <= 0.5 ? 'warn' : 'fail');
        a11y_add_check($checks, 'a11y_rgaa5_autocomplete_personal', $status, $personalInputMissingAutocomplete . '/' . $personalInputTotal, true);
    }

    // SC 3.3.8 — Accessible authentication (no cognitive captcha without alternative)
    if (!$hasCaptchaWidget) {
        a11y_add_check($checks, 'a11y_rgaa5_captcha_alternative', 'pass', 'aucun captcha detecte', true);
    } else {
        $kinds = count($captchaKinds) > 0 ? implode(', ', $captchaKinds) : 'detecte';
        a11y_add_check($checks, 'a11y_rgaa5_captcha_alternative', 'warn', $kinds . ' (verif manuelle requise)', true);
    }

    // SC 2.5.7 — Drag-and-drop alternative
    if ($draggableTotal === 0) {
        a11y_add_check($checks, 'a11y_rgaa5_drag_alternative', 'pass', '0', true);
    } else {
        a11y_add_check($checks, 'a11y_rgaa5_drag_alternative', 'warn', (string) $draggableTotal . ' element(s) draggable', true);
    }

    // SC 3.2.6 — Consistent help (presence on the page)
    a11y_add_check($checks, 'a11y_rgaa5_consistent_help', $hasHelpLink ? 'pass' : 'warn', $hasHelpLink ? 'yes' : 'no', true);

    // Modern input types — type=email/tel/url/date/number for personal/contact fields.
    if ($inputsTextShouldBeTypedTotal === 0) {
        a11y_add_check($checks, 'a11y_rgaa5_modern_input_types', 'pass', '0', true);
    } else {
        $sample = count($inputsTextShouldBeTypedExamples) > 0 ? ' (' . implode(', ', $inputsTextShouldBeTypedExamples) . ')' : '';
        $status = $inputsTextShouldBeTypedTotal >= 3 ? 'fail' : 'warn';
        a11y_add_check($checks, 'a11y_rgaa5_modern_input_types', $status, $inputsTextShouldBeTypedTotal . $sample, true);
    }

    // Landmarks completeness — header / nav / main / footer present.
    $landmarksPresent = (int) $hasHeaderLandmark + (int) $hasNavLandmark + (int) $mainLandmark + (int) $hasFooterLandmark;
    if ($landmarksPresent === 4) {
        a11y_add_check($checks, 'a11y_rgaa5_landmarks_complete', 'pass', '4/4 (header, nav, main, footer)', true);
    } else {
        $missingPieces = [];
        if (!$hasHeaderLandmark) $missingPieces[] = 'header';
        if (!$hasNavLandmark) $missingPieces[] = 'nav';
        if (!$mainLandmark) $missingPieces[] = 'main';
        if (!$hasFooterLandmark) $missingPieces[] = 'footer';
        $status = $landmarksPresent <= 2 ? 'fail' : 'warn';
        a11y_add_check($checks, 'a11y_rgaa5_landmarks_complete', $status, $landmarksPresent . '/4 (manque: ' . implode(', ', $missingPieces) . ')', true);
    }

    // Video captions track (WCAG 1.2.2).
    if ($videoTotal === 0) {
        a11y_add_check($checks, 'a11y_rgaa5_video_captions', 'pass', '0 video', true);
    } else {
        $status = $videoMissingCaptions === 0 ? 'pass' : 'fail';
        a11y_add_check($checks, 'a11y_rgaa5_video_captions', $status, $videoMissingCaptions . '/' . $videoTotal . ' sans captions', true);
    }

    // Audio transcript hint (WCAG 1.2.1).
    if ($audioTotal === 0) {
        a11y_add_check($checks, 'a11y_rgaa5_audio_transcript', 'pass', '0 audio', true);
    } else {
        $status = $audioMissingTranscriptHint === 0 ? 'pass' : 'warn';
        a11y_add_check($checks, 'a11y_rgaa5_audio_transcript', $status, $audioMissingTranscriptHint . '/' . $audioTotal . ' sans mention de transcription', true);
    }
}

$weights = [
    'a11y_http_status_2xx' => 10,
    'a11y_html_lang_present' => 8,
    'a11y_title_present' => 5,
    'a11y_viewport_present' => 4,
    'a11y_main_landmark' => 8,
    'a11y_skip_link' => 4,
    'a11y_image_alt_coverage' => 12,
    'a11y_form_labels' => 12,
    'a11y_button_names' => 10,
    'a11y_link_names' => 10,
    'a11y_iframe_titles' => 8,
    'a11y_accessibility_page' => 3,
    'a11y_accessibility_statement' => 3,
    'a11y_accessibility_multiyear' => 2,
    'a11y_accessibility_plan' => 2,
    'a11y_accessibility_status_mention' => 3,
    // Common RGAA 4 + 5 structural
    'a11y_doctype_html5' => 2,
    'a11y_charset_declared' => 3,
    'a11y_viewport_zoom_allowed' => 6,
    'a11y_heading_hierarchy' => 8,
    'a11y_tables_accessible' => 6,
    'a11y_fieldset_legend' => 5,
    'a11y_no_autoplay_media' => 6,
    // RGAA 5 / WCAG 2.2
    'a11y_rgaa5_focus_visible' => 8,
    'a11y_rgaa5_target_size' => 7,
    'a11y_rgaa5_autocomplete_personal' => 5,
    'a11y_rgaa5_captcha_alternative' => 6,
    'a11y_rgaa5_drag_alternative' => 3,
    'a11y_rgaa5_consistent_help' => 3,
    'a11y_rgaa5_modern_input_types' => 5,
    'a11y_rgaa5_landmarks_complete' => 6,
    'a11y_rgaa5_video_captions' => 7,
    'a11y_rgaa5_audio_transcript' => 4,
];
$factor = ['pass' => 1.0, 'warn' => 0.5, 'fail' => 0.0];

$counts = ['pass' => 0, 'warn' => 0, 'fail' => 0];
$weightTotal = 0.0;
$scoreRaw = 0.0;
foreach ($checks as $check) {
    $status = strtolower((string) ($check['status'] ?? 'warn'));
    $key = (string) ($check['key'] ?? '');
    if (isset($counts[$status])) {
        $counts[$status]++;
    }
    $weight = (float) ($weights[$key] ?? 0);
    $weightTotal += $weight;
    $scoreRaw += $weight * (float) ($factor[$status] ?? 0.5);
}
$score = $weightTotal > 0 ? (int) round(($scoreRaw / $weightTotal) * 100) : 0;
$score = max(0, min(100, $score));

$recommendations = [];
$pushReco = static function (array &$target, string $key): void {
    if (!in_array($key, $target, true)) {
        $target[] = $key;
    }
};

if (!$is2xx) {
    $pushReco($recommendations, 'a11y_reco_fix_http_status');
}
if (!$langPresent) {
    $pushReco($recommendations, 'a11y_reco_add_lang');
}
if (!$titlePresent) {
    $pushReco($recommendations, 'a11y_reco_add_title');
}
if (!$mainLandmark) {
    $pushReco($recommendations, 'a11y_reco_add_main_landmark');
}
if (!$skipLink) {
    $pushReco($recommendations, 'a11y_reco_add_skip_link');
}
if ($imageMissingAlt > 0) {
    $pushReco($recommendations, 'a11y_reco_fix_image_alts');
}
if ($unlabeledFormControls > 0) {
    $pushReco($recommendations, 'a11y_reco_fix_form_labels');
}
if ($unnamedButtons > 0) {
    $pushReco($recommendations, 'a11y_reco_fix_button_names');
}
if ($unnamedLinks > 0) {
    $pushReco($recommendations, 'a11y_reco_fix_link_names');
}
if ($iframeMissingTitle > 0) {
    $pushReco($recommendations, 'a11y_reco_fix_iframe_titles');
}
if (!$hasAccessibilityPage) {
    $pushReco($recommendations, 'a11y_reco_publish_accessibility_page');
}
if (!$hasAccessibilityStatement) {
    $pushReco($recommendations, 'a11y_reco_publish_statement');
}
if (!$hasMultiyearSchema) {
    $pushReco($recommendations, 'a11y_reco_publish_multiyear');
}
if (!$hasActionPlan) {
    $pushReco($recommendations, 'a11y_reco_publish_plan');
}
if (!$hasStatusMention) {
    $pushReco($recommendations, 'a11y_reco_add_status_mention');
}

// Common RGAA 4 + 5 recommendations
if (!$doctypeHtml5) {
    $pushReco($recommendations, 'a11y_reco_add_doctype_html5');
}
if (!$charsetDeclared) {
    $pushReco($recommendations, 'a11y_reco_declare_charset');
}
if ($viewportBlocksZoom) {
    $pushReco($recommendations, 'a11y_reco_allow_zoom');
}
if ($h1Count === 0 || $h1Count > 1 || $headingSkipLevels > 0) {
    $pushReco($recommendations, 'a11y_reco_fix_heading_hierarchy');
}
if ($tablesTotal > 0 && ($tablesMissingCaption > 0 || $tablesMissingTh > 0)) {
    $pushReco($recommendations, 'a11y_reco_fix_tables');
}
if ($fieldsetGroupedInputsTotal > 0 && $fieldsetMissingLegend > 0) {
    $pushReco($recommendations, 'a11y_reco_add_fieldset_legend');
}
if ($autoplayMediaTotal > 0) {
    $pushReco($recommendations, 'a11y_reco_remove_autoplay');
}

// RGAA 5-only recommendations
if ($referenceStandard === 'rgaa5') {
    if ($focusOutlineKilled && !$focusVisibleOverride) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_restore_focus_visible');
    }
    if ($smallTargetTotal > 0) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_enlarge_targets');
    }
    if ($personalInputTotal > 0 && $personalInputMissingAutocomplete > 0) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_add_autocomplete');
    }
    if ($hasCaptchaWidget) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_offer_captcha_alternative');
    }
    if ($draggableTotal > 0) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_drag_alternative');
    }
    if (!$hasHelpLink) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_consistent_help');
    }
    if ($inputsTextShouldBeTypedTotal > 0) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_modern_input_types');
    }
    if (!$hasHeaderLandmark || !$hasNavLandmark || !$mainLandmark || !$hasFooterLandmark) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_complete_landmarks');
    }
    if ($videoTotal > 0 && $videoMissingCaptions > 0) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_add_video_captions');
    }
    if ($audioTotal > 0 && $audioMissingTranscriptHint > 0) {
        $pushReco($recommendations, 'a11y_reco_rgaa5_add_audio_transcript');
    }
}

$checklistPriority = [
    'a11y_reco_fix_http_status' => 'high',
    'a11y_reco_add_lang' => 'high',
    'a11y_reco_fix_image_alts' => 'high',
    'a11y_reco_fix_form_labels' => 'high',
    'a11y_reco_fix_button_names' => 'high',
    'a11y_reco_fix_link_names' => 'high',
    'a11y_reco_add_main_landmark' => 'medium',
    'a11y_reco_add_skip_link' => 'medium',
    'a11y_reco_fix_iframe_titles' => 'medium',
    'a11y_reco_add_title' => 'medium',
    'a11y_reco_publish_accessibility_page' => 'medium',
    'a11y_reco_publish_statement' => 'medium',
    'a11y_reco_publish_multiyear' => 'low',
    'a11y_reco_publish_plan' => 'low',
    'a11y_reco_add_status_mention' => 'low',
    'a11y_reco_add_doctype_html5' => 'low',
    'a11y_reco_declare_charset' => 'low',
    'a11y_reco_allow_zoom' => 'high',
    'a11y_reco_fix_heading_hierarchy' => 'high',
    'a11y_reco_fix_tables' => 'medium',
    'a11y_reco_add_fieldset_legend' => 'medium',
    'a11y_reco_remove_autoplay' => 'high',
    // RGAA 5
    'a11y_reco_rgaa5_restore_focus_visible' => 'high',
    'a11y_reco_rgaa5_add_autocomplete' => 'high',
    'a11y_reco_rgaa5_offer_captcha_alternative' => 'high',
    'a11y_reco_rgaa5_enlarge_targets' => 'medium',
    'a11y_reco_rgaa5_drag_alternative' => 'medium',
    'a11y_reco_rgaa5_consistent_help' => 'low',
    'a11y_reco_rgaa5_modern_input_types' => 'medium',
    'a11y_reco_rgaa5_complete_landmarks' => 'medium',
    'a11y_reco_rgaa5_add_video_captions' => 'high',
    'a11y_reco_rgaa5_add_audio_transcript' => 'medium',
];
$checklist = ['high' => [], 'medium' => [], 'low' => []];
foreach ($recommendations as $recoKey) {
    $priority = (string) ($checklistPriority[$recoKey] ?? 'medium');
    if (!isset($checklist[$priority])) {
        $priority = 'medium';
    }
    $checklist[$priority][] = $recoKey;
}

$accessibilitySignals = (int) $hasAccessibilityPage + (int) $hasAccessibilityStatement + (int) $hasMultiyearSchema + (int) $hasActionPlan + (int) $hasStatusMention;

respond_json([
    'audit' => [
        'url' => $url,
        'reference_standard' => $referenceStandard,
        'final_url' => $finalUrl,
        'status_code' => $statusCode,
        'response_time_ms' => $responseMs,
        'content_type' => $contentType,
        'redirect_count' => $redirectCount,
        'redirect_chain' => $redirectChain,
        'score' => $score,
        'counts' => $counts,
        'checks' => $checks,
        'metrics' => [
            'reference_standard' => $referenceStandard,
            'html_lang' => (string) ($signals['html_lang'] ?? ''),
            'title_present' => $titlePresent,
            'main_landmark' => $mainLandmark,
            'skip_link' => $skipLink,
            'image_total' => $imageTotal,
            'image_missing_alt' => $imageMissingAlt,
            'image_empty_alt' => (int) ($signals['image_empty_alt'] ?? 0),
            'form_control_total' => $formControlTotal,
            'unlabeled_form_controls' => $unlabeledFormControls,
            'button_total' => $buttonTotal,
            'unnamed_buttons' => $unnamedButtons,
            'link_total' => $linkTotal,
            'unnamed_links' => $unnamedLinks,
            'iframe_total' => $iframeTotal,
            'iframe_missing_title' => $iframeMissingTitle,
            'has_accessibility_page' => $hasAccessibilityPage,
            'has_accessibility_statement' => $hasAccessibilityStatement,
            'has_multiyear_schema' => $hasMultiyearSchema,
            'has_action_plan' => $hasActionPlan,
            'has_status_mention' => $hasStatusMention,
            'accessibility_signals' => $accessibilitySignals,
            'rgaa5_focus_outline_killed' => $focusOutlineKilled,
            'rgaa5_focus_visible_override' => $focusVisibleOverride,
            'rgaa5_small_target_total' => $smallTargetTotal,
            'rgaa5_small_target_examples' => $smallTargetExamples,
            'rgaa5_personal_input_total' => $personalInputTotal,
            'rgaa5_personal_input_missing_autocomplete' => $personalInputMissingAutocomplete,
            'rgaa5_has_captcha_widget' => $hasCaptchaWidget,
            'rgaa5_captcha_kinds' => $captchaKinds,
            'rgaa5_draggable_total' => $draggableTotal,
            'rgaa5_has_help_link' => $hasHelpLink,
            'rgaa5_inputs_text_should_be_typed_total' => $inputsTextShouldBeTypedTotal,
            'rgaa5_inputs_text_should_be_typed_examples' => $inputsTextShouldBeTypedExamples,
            'rgaa5_has_header_landmark' => $hasHeaderLandmark,
            'rgaa5_has_nav_landmark' => $hasNavLandmark,
            'rgaa5_has_footer_landmark' => $hasFooterLandmark,
            'rgaa5_video_total' => $videoTotal,
            'rgaa5_video_missing_captions' => $videoMissingCaptions,
            'rgaa5_audio_total' => $audioTotal,
            'rgaa5_audio_missing_transcript_hint' => $audioMissingTranscriptHint,
        ],
        'recommendations' => $recommendations,
        'checklist' => $checklist,
    ],
]);
