<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

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
    ];

    if (!class_exists('DOMDocument')) {
        return $empty;
    }
    if (trim($html) === '') {
        return $empty;
    }

    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    $loaded = @$dom->loadHTML('<?xml encoding="utf-8" ?>' . $html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
    if ($loaded === false) {
        return $empty;
    }

    $xpath = new DOMXPath($dom);
    $htmlLang = trim((string) a11y_dom_first_attr($xpath, '//html', 'lang'));
    $title = trim((string) $dom->getElementsByTagName('title')->item(0)?->textContent);
    $viewportPresent = a11y_dom_first_attr(
        $xpath,
        '//meta[translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="viewport"]',
        'content'
    ) !== '';

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
    ];
}

function a11y_add_check(array &$checks, string $key, string $status, string $value): void
{
    $safe = strtolower(trim($status));
    if (!in_array($safe, ['pass', 'warn', 'fail'], true)) {
        $safe = 'warn';
    }
    $checks[] = [
        'key' => $key,
        'status' => $safe,
        'value' => $value,
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
        ],
        'recommendations' => $recommendations,
        'checklist' => $checklist,
    ],
]);
