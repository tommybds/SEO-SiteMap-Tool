<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('tech_audit_run', $ip, 18, 600);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit audit technique atteint. Reessaye plus tard.',
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
$maxRedirects = 8;

if (!function_exists('curl_init')) {
    respond_json(['error' => 'cURL est indisponible sur cet hebergement.'], 500);
}

function tech_strlen(string $value): int
{
    if (function_exists('mb_strlen')) {
        return (int) mb_strlen($value, 'UTF-8');
    }
    return strlen($value);
}

function tech_resolve_url(string $baseUrl, string $target): ?string
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

function tech_parse_header_block(string $rawHeaders): array
{
    $headers = [];
    $lines = preg_split('/\r\n|\n|\r/', trim($rawHeaders)) ?: [];
    foreach ($lines as $line) {
        if (!is_string($line) || trim($line) === '' || !str_contains($line, ':')) {
            continue;
        }
        [$name, $value] = explode(':', $line, 2);
        $key = strtolower(trim($name));
        if ($key === '') {
            continue;
        }
        $headers[$key] ??= [];
        $headers[$key][] = trim((string) $value);
    }
    return $headers;
}

function tech_parse_headers_with_intermediate(string $rawHeaders): array
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
        $headers = tech_parse_header_block($block);
        $parsed[] = [
            'status_line' => $statusLine,
            'headers' => $headers,
        ];
    }
    return $parsed;
}

function tech_fetch_once(string $url, int $timeout, bool $headOnly = false): array
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
        CURLOPT_USERAGENT => 'SEO-Sitemap-Tool-TechAudit/1.2',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
        CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $resolvedIp],
        CURLOPT_HTTPHEADER => [
            'Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.7',
        ],
        CURLOPT_NOBODY => $headOnly,
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
    $body = $headOnly ? '' : (string) substr($raw, max(0, $headerSize));
    if (!is_string($headerChunk)) {
        return ['ok' => false, 'error' => 'Reponse HTTP invalide.'];
    }

    $headerBlocks = tech_parse_headers_with_intermediate($headerChunk);
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

function tech_fetch_with_redirects(string $url, int $timeout, int $maxRedirects, bool $headOnly = false): array
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

        $fetch = tech_fetch_once($currentUrl, $timeout, $headOnly);
        if (empty($fetch['ok'])) {
            return [
                'ok' => false,
                'error' => (string) ($fetch['error'] ?? 'Erreur fetch URL.'),
                'redirect_chain' => $chain,
            ];
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
            $nextUrl = tech_resolve_url($currentUrl, $location);
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
            'requested_url' => $url,
            'final_url' => $currentUrl,
            'status_code' => $statusCode,
            'redirect_count' => $redirectCount,
            'response_time_ms' => (int) ($fetch['response_time_ms'] ?? 0),
            'content_type' => (string) ($fetch['content_type'] ?? ''),
            'headers' => is_array($fetch['headers'] ?? null) ? $fetch['headers'] : [],
            'body' => (string) ($fetch['body'] ?? ''),
            'redirect_chain' => $chain,
        ];
    }
}

function tech_dom_first_text(DOMXPath $xpath, string $query): string
{
    $nodes = $xpath->query($query);
    if (!($nodes instanceof DOMNodeList) || $nodes->length === 0) {
        return '';
    }
    $node = $nodes->item(0);
    if (!($node instanceof DOMNode)) {
        return '';
    }
    return trim((string) $node->textContent);
}

function tech_dom_first_attr(DOMXPath $xpath, string $query, string $attribute): string
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

function tech_collect_jsonld_types(mixed $node, array &$types, int &$typedItems): void
{
    if (is_array($node)) {
        $isAssoc = array_keys($node) !== range(0, count($node) - 1);
        if ($isAssoc && array_key_exists('@type', $node)) {
            $typeValue = $node['@type'];
            if (is_string($typeValue) && trim($typeValue) !== '') {
                $types[strtolower(trim($typeValue))] = true;
                $typedItems++;
            } elseif (is_array($typeValue)) {
                foreach ($typeValue as $subType) {
                    if (is_string($subType) && trim($subType) !== '') {
                        $types[strtolower(trim($subType))] = true;
                    }
                }
                $typedItems++;
            }
        }
        foreach ($node as $value) {
            tech_collect_jsonld_types($value, $types, $typedItems);
        }
    }
}

function tech_parse_html_signals(string $html, string $finalUrl): array
{
    $empty = [
        'title' => '',
        'title_length' => 0,
        'meta_description' => '',
        'meta_description_length' => 0,
        'h1_count' => 0,
        'canonical_url' => '',
        'canonical_count' => 0,
        'canonical_cross_domain' => false,
        'robots_meta' => '',
        'robots_meta_noindex' => false,
        'hreflang_count' => 0,
        'hreflang_has_x_default' => false,
        'og' => ['title' => false, 'description' => false, 'image' => false, 'url' => false, 'type' => false],
        'og_image_url' => '',
        'twitter' => ['card' => false, 'title' => false, 'description' => false, 'image' => false],
        'json_ld_count' => 0,
        'json_ld_valid_count' => 0,
        'json_ld_invalid_count' => 0,
        'json_ld_types' => [],
        'json_ld_typed_items' => 0,
        'viewport_present' => false,
        'internal_links_count' => 0,
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
    $title = tech_dom_first_text($xpath, '//title');
    $metaDescription = tech_dom_first_attr(
        $xpath,
        '//meta[translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="description"]',
        'content'
    );
    $h1Nodes = $xpath->query('//h1');
    $h1Count = ($h1Nodes instanceof DOMNodeList) ? $h1Nodes->length : 0;

    $canonicalNodes = $xpath->query('//link[contains(concat(" ", translate(@rel,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"), " "), " canonical ")]');
    $canonicalCount = ($canonicalNodes instanceof DOMNodeList) ? $canonicalNodes->length : 0;
    $canonicalRaw = tech_dom_first_attr(
        $xpath,
        '//link[contains(concat(" ", translate(@rel,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"), " "), " canonical ")]',
        'href'
    );

    $canonicalUrl = '';
    if ($canonicalRaw !== '') {
        $resolvedCanonical = tech_resolve_url($finalUrl, $canonicalRaw);
        $canonicalUrl = $resolvedCanonical ?: $canonicalRaw;
    }

    $finalHost = strtolower((string) parse_url($finalUrl, PHP_URL_HOST));
    $canonicalHost = strtolower((string) parse_url($canonicalUrl, PHP_URL_HOST));
    $canonicalCrossDomain = $canonicalUrl !== '' && $canonicalHost !== '' && $finalHost !== '' && $canonicalHost !== $finalHost;

    $robotsMetaValues = [];
    $robotsNodes = $xpath->query(
        '//meta[translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="robots"'
        . ' or translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="googlebot"]'
    );
    if ($robotsNodes instanceof DOMNodeList) {
        foreach ($robotsNodes as $node) {
            if ($node instanceof DOMElement) {
                $content = trim((string) $node->getAttribute('content'));
                if ($content !== '') {
                    $robotsMetaValues[] = $content;
                }
            }
        }
    }
    $robotsMeta = implode(', ', $robotsMetaValues);
    $robotsMetaNoindex = str_contains(strtolower($robotsMeta), 'noindex');

    $hreflangCount = 0;
    $hreflangHasXDefault = false;
    $hreflangNodes = $xpath->query(
        '//link[contains(concat(" ", translate(@rel,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"), " "), " alternate ") and @hreflang]'
    );
    if ($hreflangNodes instanceof DOMNodeList) {
        $hreflangCount = $hreflangNodes->length;
        foreach ($hreflangNodes as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $code = strtolower(trim((string) $node->getAttribute('hreflang')));
            if ($code === 'x-default') {
                $hreflangHasXDefault = true;
                break;
            }
        }
    }

    $ogNodes = $xpath->query('//meta[starts-with(translate(@property,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"og:")]');
    $ogMap = ['title' => false, 'description' => false, 'image' => false, 'url' => false, 'type' => false];
    $ogImageUrl = '';
    if ($ogNodes instanceof DOMNodeList) {
        foreach ($ogNodes as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $property = strtolower(trim((string) $node->getAttribute('property')));
            $content = trim((string) $node->getAttribute('content'));
            if ($content === '') {
                continue;
            }
            if ($property === 'og:title') {
                $ogMap['title'] = true;
            } elseif ($property === 'og:description') {
                $ogMap['description'] = true;
            } elseif ($property === 'og:image') {
                $ogMap['image'] = true;
                if ($ogImageUrl === '') {
                    $resolved = tech_resolve_url($finalUrl, $content);
                    $ogImageUrl = $resolved ?: $content;
                }
            } elseif ($property === 'og:url') {
                $ogMap['url'] = true;
            } elseif ($property === 'og:type') {
                $ogMap['type'] = true;
            }
        }
    }

    $twitterNodes = $xpath->query('//meta[starts-with(translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"twitter:")]');
    $twitterMap = ['card' => false, 'title' => false, 'description' => false, 'image' => false];
    if ($twitterNodes instanceof DOMNodeList) {
        foreach ($twitterNodes as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $name = strtolower(trim((string) $node->getAttribute('name')));
            $content = trim((string) $node->getAttribute('content'));
            if ($content === '') {
                continue;
            }
            if ($name === 'twitter:card') {
                $twitterMap['card'] = true;
            } elseif ($name === 'twitter:title') {
                $twitterMap['title'] = true;
            } elseif ($name === 'twitter:description') {
                $twitterMap['description'] = true;
            } elseif ($name === 'twitter:image' || $name === 'twitter:image:src') {
                $twitterMap['image'] = true;
            }
        }
    }

    $jsonLdNodes = $xpath->query('//script[translate(@type,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="application/ld+json"]');
    $jsonLdCount = ($jsonLdNodes instanceof DOMNodeList) ? $jsonLdNodes->length : 0;
    $jsonLdValid = 0;
    $jsonLdInvalid = 0;
    $jsonLdTypesSet = [];
    $jsonLdTypedItems = 0;

    if ($jsonLdNodes instanceof DOMNodeList) {
        foreach ($jsonLdNodes as $node) {
            if (!($node instanceof DOMNode)) {
                continue;
            }
            $raw = trim((string) $node->textContent);
            if ($raw === '') {
                $jsonLdInvalid++;
                continue;
            }
            try {
                $decoded = json_decode($raw, true, 128, JSON_THROW_ON_ERROR);
                $jsonLdValid++;
                tech_collect_jsonld_types($decoded, $jsonLdTypesSet, $jsonLdTypedItems);
            } catch (Throwable $e) {
                $jsonLdInvalid++;
            }
        }
    }

    $viewportPresent = tech_dom_first_attr(
        $xpath,
        '//meta[translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="viewport"]',
        'content'
    ) !== '';

    $internalLinks = [];
    $linkNodes = $xpath->query('//a[@href]');
    if ($linkNodes instanceof DOMNodeList) {
        foreach ($linkNodes as $node) {
            if (!($node instanceof DOMElement)) {
                continue;
            }
            $href = trim((string) $node->getAttribute('href'));
            if ($href === '' || str_starts_with($href, '#') || str_starts_with(strtolower($href), 'javascript:') || str_starts_with(strtolower($href), 'mailto:')) {
                continue;
            }
            $resolved = tech_resolve_url($finalUrl, $href);
            if (!is_string($resolved) || $resolved === '') {
                continue;
            }
            $host = strtolower((string) parse_url($resolved, PHP_URL_HOST));
            if ($host !== '' && $finalHost !== '' && $host === $finalHost) {
                $internalLinks[$resolved] = true;
            }
        }
    }

    $jsonLdTypes = array_keys($jsonLdTypesSet);
    sort($jsonLdTypes);

    return [
        'title' => $title,
        'title_length' => tech_strlen($title),
        'meta_description' => $metaDescription,
        'meta_description_length' => tech_strlen($metaDescription),
        'h1_count' => $h1Count,
        'canonical_url' => $canonicalUrl,
        'canonical_count' => $canonicalCount,
        'canonical_cross_domain' => $canonicalCrossDomain,
        'robots_meta' => $robotsMeta,
        'robots_meta_noindex' => $robotsMetaNoindex,
        'hreflang_count' => $hreflangCount,
        'hreflang_has_x_default' => $hreflangHasXDefault,
        'og' => $ogMap,
        'og_image_url' => $ogImageUrl,
        'twitter' => $twitterMap,
        'json_ld_count' => $jsonLdCount,
        'json_ld_valid_count' => $jsonLdValid,
        'json_ld_invalid_count' => $jsonLdInvalid,
        'json_ld_types' => $jsonLdTypes,
        'json_ld_typed_items' => $jsonLdTypedItems,
        'viewport_present' => $viewportPresent,
        'internal_links_count' => count($internalLinks),
    ];
}

function tech_parse_robots_groups(string $content): array
{
    $groups = [];
    $current = ['agents' => [], 'rules' => []];
    $hasRules = false;

    $lines = preg_split('/\r\n|\n|\r/', $content) ?: [];
    foreach ($lines as $line) {
        if (!is_string($line)) {
            continue;
        }
        $line = preg_replace('/\s*#.*$/', '', $line);
        $line = trim((string) $line);
        if ($line === '' || !str_contains($line, ':')) {
            continue;
        }

        [$rawKey, $rawValue] = explode(':', $line, 2);
        $key = strtolower(trim($rawKey));
        $value = trim($rawValue);

        if ($key === 'user-agent') {
            if ($hasRules && (count($current['agents']) > 0 || count($current['rules']) > 0)) {
                $groups[] = $current;
                $current = ['agents' => [], 'rules' => []];
                $hasRules = false;
            }
            if ($value !== '') {
                $current['agents'][] = strtolower($value);
            }
            continue;
        }

        if ($key === 'allow' || $key === 'disallow') {
            if (count($current['agents']) === 0) {
                $current['agents'][] = '*';
            }
            $current['rules'][] = [
                'type' => $key,
                'path' => $value,
            ];
            $hasRules = true;
        }
    }

    if (count($current['agents']) > 0 || count($current['rules']) > 0) {
        $groups[] = $current;
    }

    return $groups;
}

function tech_pick_robots_rules(array $groups, string $userAgent): array
{
    $ua = strtolower(trim($userAgent));
    $bestScore = -1;
    $bestRules = [];

    foreach ($groups as $group) {
        $agents = is_array($group['agents'] ?? null) ? $group['agents'] : [];
        $rules = is_array($group['rules'] ?? null) ? $group['rules'] : [];
        foreach ($agents as $agent) {
            $agent = strtolower(trim((string) $agent));
            if ($agent === '') {
                continue;
            }
            $score = -1;
            if ($agent === '*') {
                $score = 0;
            } elseif (str_contains($ua, $agent)) {
                $score = strlen($agent);
            }
            if ($score > $bestScore) {
                $bestScore = $score;
                $bestRules = $rules;
            }
        }
    }

    return $bestRules;
}

function tech_robots_rule_matches(string $rulePath, string $targetPath): bool
{
    $rulePath = trim($rulePath);
    if ($rulePath === '') {
        return false;
    }

    $targetPath = trim($targetPath);
    if ($targetPath === '') {
        $targetPath = '/';
    }

    if (preg_match('/^https?:\/\//i', $rulePath)) {
        $path = (string) parse_url($rulePath, PHP_URL_PATH);
        $query = (string) parse_url($rulePath, PHP_URL_QUERY);
        $rulePath = $query !== '' ? ($path . '?' . $query) : $path;
    }

    $anchored = str_ends_with($rulePath, '$');
    if ($anchored) {
        $rulePath = substr($rulePath, 0, -1);
    }

    $pattern = preg_quote($rulePath, '#');
    $pattern = str_replace('\\*', '.*', $pattern);
    $regex = '#^' . $pattern . ($anchored ? '$' : '') . '#i';
    return (bool) preg_match($regex, $targetPath);
}

function tech_robots_is_blocked(array $rules, string $targetPath): array
{
    $bestLength = -1;
    $bestType = 'allow';
    $bestPath = '';

    foreach ($rules as $rule) {
        $type = strtolower(trim((string) ($rule['type'] ?? '')));
        $path = trim((string) ($rule['path'] ?? ''));
        if (!in_array($type, ['allow', 'disallow'], true)) {
            continue;
        }
        if ($type === 'disallow' && $path === '') {
            continue;
        }
        if (!tech_robots_rule_matches($path, $targetPath)) {
            continue;
        }

        $length = strlen($path);
        if ($length > $bestLength || ($length === $bestLength && $type === 'allow')) {
            $bestLength = $length;
            $bestType = $type;
            $bestPath = $path;
        }
    }

    return [
        'blocked' => $bestLength >= 0 && $bestType === 'disallow',
        'matched_rule' => $bestLength >= 0 ? ($bestType . ':' . $bestPath) : '',
    ];
}

function tech_fetch_robots_for_url(string $targetUrl, int $timeout): array
{
    $parts = parse_url($targetUrl);
    if (!is_array($parts)) {
        return [
            'url' => '',
            'status_code' => 0,
            'found' => false,
            'blocked' => false,
            'matched_rule' => '',
            'error' => 'URL cible invalide pour robots.txt',
        ];
    }

    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = strtolower((string) ($parts['host'] ?? ''));
    if ($scheme === '' || $host === '') {
        return [
            'url' => '',
            'status_code' => 0,
            'found' => false,
            'blocked' => false,
            'matched_rule' => '',
            'error' => 'Host/scheme indisponible pour robots.txt',
        ];
    }

    $robotsUrl = $scheme . '://' . $host . '/robots.txt';
    $validationError = '';
    if (!validate_public_url($robotsUrl, $validationError)) {
        return [
            'url' => $robotsUrl,
            'status_code' => 0,
            'found' => false,
            'blocked' => false,
            'matched_rule' => '',
            'error' => $validationError,
        ];
    }

    $fetch = tech_fetch_with_redirects($robotsUrl, $timeout, 2, false);
    if (empty($fetch['ok'])) {
        return [
            'url' => $robotsUrl,
            'status_code' => 0,
            'found' => false,
            'blocked' => false,
            'matched_rule' => '',
            'error' => (string) ($fetch['error'] ?? 'Erreur robots.txt'),
        ];
    }

    $statusCode = (int) ($fetch['status_code'] ?? 0);
    $body = (string) ($fetch['body'] ?? '');
    $targetPath = (string) parse_url($targetUrl, PHP_URL_PATH);
    $targetQuery = (string) parse_url($targetUrl, PHP_URL_QUERY);
    if ($targetPath === '') {
        $targetPath = '/';
    }
    $pathForRules = $targetQuery !== '' ? ($targetPath . '?' . $targetQuery) : $targetPath;

    $blocked = false;
    $matchedRule = '';
    if ($statusCode >= 200 && $statusCode < 300 && $body !== '') {
        $groups = tech_parse_robots_groups($body);
        $rules = tech_pick_robots_rules($groups, 'googlebot');
        if (count($rules) === 0) {
            $rules = tech_pick_robots_rules($groups, '*');
        }
        $decision = tech_robots_is_blocked($rules, $pathForRules);
        $blocked = (bool) ($decision['blocked'] ?? false);
        $matchedRule = (string) ($decision['matched_rule'] ?? '');
    }

    return [
        'url' => (string) ($fetch['final_url'] ?? $robotsUrl),
        'status_code' => $statusCode,
        'found' => $statusCode >= 200 && $statusCode < 300,
        'blocked' => $blocked,
        'matched_rule' => $matchedRule,
        'error' => '',
    ];
}

function tech_extract_noindex_from_headers(array $headers): bool
{
    $xRobots = strtolower(trim((string) ($headers['x-robots-tag'] ?? '')));
    return str_contains($xRobots, 'noindex');
}

function tech_analyze_canonical_target(string $canonicalUrl, int $timeout, string $pageHost): array
{
    if ($canonicalUrl === '') {
        return [
            'present' => false,
            'url' => '',
            'valid_public' => false,
            'status_code' => 0,
            'is_2xx' => false,
            'cross_domain' => false,
            'noindex' => false,
            'error' => '',
        ];
    }

    $validationError = '';
    if (!validate_public_url($canonicalUrl, $validationError)) {
        return [
            'present' => true,
            'url' => $canonicalUrl,
            'valid_public' => false,
            'status_code' => 0,
            'is_2xx' => false,
            'cross_domain' => false,
            'noindex' => false,
            'error' => $validationError,
        ];
    }

    $fetch = tech_fetch_with_redirects($canonicalUrl, $timeout, 3, false);
    if (empty($fetch['ok'])) {
        return [
            'present' => true,
            'url' => $canonicalUrl,
            'valid_public' => true,
            'status_code' => 0,
            'is_2xx' => false,
            'cross_domain' => false,
            'noindex' => false,
            'error' => (string) ($fetch['error'] ?? 'Erreur canonical target'),
        ];
    }

    $finalUrl = (string) ($fetch['final_url'] ?? $canonicalUrl);
    $statusCode = (int) ($fetch['status_code'] ?? 0);
    $headers = is_array($fetch['headers'] ?? null) ? $fetch['headers'] : [];
    $body = (string) ($fetch['body'] ?? '');
    $contentType = strtolower((string) ($fetch['content_type'] ?? ''));

    $finalHost = strtolower((string) parse_url($finalUrl, PHP_URL_HOST));
    $crossDomain = ($pageHost !== '' && $finalHost !== '' && $finalHost !== $pageHost);

    $noindex = tech_extract_noindex_from_headers($headers);
    if (!$noindex && (str_contains($contentType, 'text/html') || str_contains(strtolower(substr($body, 0, 1200)), '<html'))) {
        $signals = tech_parse_html_signals($body, $finalUrl);
        $noindex = (bool) ($signals['robots_meta_noindex'] ?? false);
    }

    return [
        'present' => true,
        'url' => $finalUrl,
        'valid_public' => true,
        'status_code' => $statusCode,
        'is_2xx' => $statusCode >= 200 && $statusCode < 300,
        'cross_domain' => $crossDomain,
        'noindex' => $noindex,
        'error' => '',
    ];
}

function tech_analyze_og_image(string $ogImageUrl, int $timeout): array
{
    if ($ogImageUrl === '') {
        return [
            'present' => false,
            'url' => '',
            'status_code' => 0,
            'fetchable' => false,
            'image_content_type' => false,
            'content_type' => '',
            'error' => '',
        ];
    }

    $validationError = '';
    if (!validate_public_url($ogImageUrl, $validationError)) {
        return [
            'present' => true,
            'url' => $ogImageUrl,
            'status_code' => 0,
            'fetchable' => false,
            'image_content_type' => false,
            'content_type' => '',
            'error' => $validationError,
        ];
    }

    $fetch = tech_fetch_with_redirects($ogImageUrl, $timeout, 3, true);
    if (empty($fetch['ok'])) {
        return [
            'present' => true,
            'url' => $ogImageUrl,
            'status_code' => 0,
            'fetchable' => false,
            'image_content_type' => false,
            'content_type' => '',
            'error' => (string) ($fetch['error'] ?? 'Erreur OG image'),
        ];
    }

    $statusCode = (int) ($fetch['status_code'] ?? 0);
    $contentType = strtolower((string) ($fetch['content_type'] ?? ''));

    return [
        'present' => true,
        'url' => (string) ($fetch['final_url'] ?? $ogImageUrl),
        'status_code' => $statusCode,
        'fetchable' => $statusCode >= 200 && $statusCode < 300,
        'image_content_type' => str_starts_with($contentType, 'image/'),
        'content_type' => $contentType,
        'error' => '',
    ];
}

function tech_add_check(array &$checks, string $key, string $status, string $value = ''): void
{
    $status = in_array($status, ['pass', 'warn', 'fail'], true) ? $status : 'warn';
    $checks[] = [
        'key' => $key,
        'status' => $status,
        'value' => $value,
    ];
}

$fetch = tech_fetch_with_redirects($url, $timeout, $maxRedirects, false);
if (empty($fetch['ok'])) {
    respond_json(['error' => (string) ($fetch['error'] ?? 'Erreur audit URL.')], 400);
}

$finalUrl = (string) ($fetch['final_url'] ?? $url);
$statusCode = (int) ($fetch['status_code'] ?? 0);
$contentType = strtolower((string) ($fetch['content_type'] ?? ''));
$headers = is_array($fetch['headers'] ?? null) ? $fetch['headers'] : [];
$body = (string) ($fetch['body'] ?? '');
$redirectCount = (int) ($fetch['redirect_count'] ?? 0);
$redirectChain = is_array($fetch['redirect_chain'] ?? null) ? $fetch['redirect_chain'] : [];
$isHtml = str_contains($contentType, 'text/html') || str_contains(strtolower(substr($body, 0, 1200)), '<html');

$signals = tech_parse_html_signals($body, $finalUrl);
$robots = tech_fetch_robots_for_url($finalUrl, $timeout);

$xRobotsNoindex = tech_extract_noindex_from_headers($headers);
$robotsMetaNoindex = (bool) ($signals['robots_meta_noindex'] ?? false);

$scheme = strtolower((string) parse_url($finalUrl, PHP_URL_SCHEME));
$pageHost = strtolower((string) parse_url($finalUrl, PHP_URL_HOST));
$isHttps = $scheme === 'https';
$is2xx = $statusCode >= 200 && $statusCode < 300;
$blockedByRobots = (bool) ($robots['blocked'] ?? false);
$indexable = $is2xx && !$blockedByRobots && !$robotsMetaNoindex && !$xRobotsNoindex;

$titleLength = (int) ($signals['title_length'] ?? 0);
$metaLength = (int) ($signals['meta_description_length'] ?? 0);
$h1Count = (int) ($signals['h1_count'] ?? 0);
$canonicalUrl = (string) ($signals['canonical_url'] ?? '');
$canonicalCrossDomain = (bool) ($signals['canonical_cross_domain'] ?? false);
$canonicalCount = (int) ($signals['canonical_count'] ?? 0);
$hreflangCount = (int) ($signals['hreflang_count'] ?? 0);
$hreflangHasXDefault = (bool) ($signals['hreflang_has_x_default'] ?? false);
$jsonLdCount = (int) ($signals['json_ld_count'] ?? 0);
$jsonLdValidCount = (int) ($signals['json_ld_valid_count'] ?? 0);
$jsonLdInvalidCount = (int) ($signals['json_ld_invalid_count'] ?? 0);
$jsonLdTypedItems = (int) ($signals['json_ld_typed_items'] ?? 0);
$jsonLdTypes = is_array($signals['json_ld_types'] ?? null) ? $signals['json_ld_types'] : [];
$viewportPresent = (bool) ($signals['viewport_present'] ?? false);
$internalLinksCount = (int) ($signals['internal_links_count'] ?? 0);

$og = is_array($signals['og'] ?? null) ? $signals['og'] : [];
$twitter = is_array($signals['twitter'] ?? null) ? $signals['twitter'] : [];
$ogComplete = !empty($og['title']) && !empty($og['description']) && !empty($og['image']);
$twitterComplete = !empty($twitter['card']) && !empty($twitter['title']) && !empty($twitter['description']);
$twitterImagePresent = !empty($twitter['image']);

$canonicalTarget = tech_analyze_canonical_target($canonicalUrl, $timeout, $pageHost);
$canonicalTarget2xx = (bool) ($canonicalTarget['is_2xx'] ?? false);
$canonicalTargetNoindex = (bool) ($canonicalTarget['noindex'] ?? false);
$canonicalTargetCrossDomain = (bool) ($canonicalTarget['cross_domain'] ?? false);

$ogImageInfo = tech_analyze_og_image((string) ($signals['og_image_url'] ?? ''), $timeout);
$ogImageFetchable = (bool) ($ogImageInfo['fetchable'] ?? false);
$ogImageLooksImage = (bool) ($ogImageInfo['image_content_type'] ?? false);

$redirectChainTooLong = $redirectCount >= 3;
$redirectHttpsOnly = true;
foreach ($redirectChain as $step) {
    if (!is_array($step)) {
        continue;
    }
    $stepUrl = (string) ($step['url'] ?? '');
    $stepScheme = strtolower((string) parse_url($stepUrl, PHP_URL_SCHEME));
    if ($stepScheme !== '' && $stepScheme !== 'https') {
        $redirectHttpsOnly = false;
        break;
    }
}

$effectiveIndexabilityConflict = false;
$effectiveIndexabilityDetail = 'ok';
if ($indexable && ($blockedByRobots || $robotsMetaNoindex || $xRobotsNoindex)) {
    $effectiveIndexabilityConflict = true;
    $effectiveIndexabilityDetail = 'indexable=true with blocking signal';
} elseif ($canonicalUrl !== '' && (!$canonicalTarget2xx || $canonicalTargetNoindex)) {
    $effectiveIndexabilityConflict = true;
    $effectiveIndexabilityDetail = !$canonicalTarget2xx ? 'canonical target non-2xx' : 'canonical target noindex';
}

$checks = [];
tech_add_check($checks, 'http_status_200', $is2xx ? 'pass' : 'fail', (string) $statusCode);
tech_add_check($checks, 'https', $isHttps ? 'pass' : 'fail', $scheme !== '' ? $scheme : '-');
tech_add_check($checks, 'redirect_chain_length', $redirectCount <= 1 ? 'pass' : ($redirectChainTooLong ? 'fail' : 'warn'), (string) $redirectCount);
tech_add_check($checks, 'redirect_chain_https', $redirectHttpsOnly ? 'pass' : 'warn', $redirectHttpsOnly ? 'https-only' : 'mixed');
tech_add_check($checks, 'html_content_type', $isHtml ? 'pass' : 'warn', $contentType !== '' ? $contentType : '-');
tech_add_check($checks, 'indexable', $indexable ? 'pass' : 'fail', $indexable ? 'yes' : 'no');
tech_add_check($checks, 'effective_indexability_conflict', $effectiveIndexabilityConflict ? 'fail' : 'pass', $effectiveIndexabilityDetail);
tech_add_check($checks, 'title_present', $titleLength > 0 ? 'pass' : 'fail', (string) $titleLength);

if ($titleLength === 0) {
    tech_add_check($checks, 'title_length', 'fail', (string) $titleLength);
} elseif ($titleLength >= 30 && $titleLength <= 65) {
    tech_add_check($checks, 'title_length', 'pass', (string) $titleLength);
} elseif (($titleLength >= 20 && $titleLength < 30) || ($titleLength > 65 && $titleLength <= 75)) {
    tech_add_check($checks, 'title_length', 'warn', (string) $titleLength);
} else {
    tech_add_check($checks, 'title_length', 'fail', (string) $titleLength);
}

tech_add_check($checks, 'meta_description_present', $metaLength > 0 ? 'pass' : 'fail', (string) $metaLength);
if ($metaLength === 0) {
    tech_add_check($checks, 'meta_description_length', 'fail', (string) $metaLength);
} elseif ($metaLength >= 70 && $metaLength <= 160) {
    tech_add_check($checks, 'meta_description_length', 'pass', (string) $metaLength);
} elseif (($metaLength >= 50 && $metaLength < 70) || ($metaLength > 160 && $metaLength <= 180)) {
    tech_add_check($checks, 'meta_description_length', 'warn', (string) $metaLength);
} else {
    tech_add_check($checks, 'meta_description_length', 'fail', (string) $metaLength);
}

if ($h1Count === 1) {
    tech_add_check($checks, 'h1_single', 'pass', (string) $h1Count);
} elseif ($h1Count === 0) {
    tech_add_check($checks, 'h1_single', 'fail', (string) $h1Count);
} else {
    tech_add_check($checks, 'h1_single', 'warn', (string) $h1Count);
}

tech_add_check($checks, 'canonical_present', $canonicalUrl !== '' ? 'pass' : 'warn', $canonicalUrl !== '' ? $canonicalUrl : '-');
tech_add_check($checks, 'canonical_count_single', $canonicalCount === 1 ? 'pass' : ($canonicalCount === 0 ? 'warn' : 'fail'), (string) $canonicalCount);
if ($canonicalUrl === '') {
    tech_add_check($checks, 'canonical_self_domain', 'warn', '-');
    tech_add_check($checks, 'canonical_target_status', 'warn', '-');
    tech_add_check($checks, 'canonical_target_indexable', 'warn', '-');
} else {
    tech_add_check($checks, 'canonical_self_domain', $canonicalCrossDomain ? 'fail' : 'pass', $canonicalCrossDomain ? 'cross-domain' : 'ok');
    tech_add_check($checks, 'canonical_target_status', $canonicalTarget2xx ? 'pass' : 'fail', (string) ($canonicalTarget['status_code'] ?? 0));
    if (!$canonicalTarget2xx) {
        tech_add_check($checks, 'canonical_target_indexable', 'fail', 'non-2xx');
    } elseif ($canonicalTargetNoindex) {
        tech_add_check($checks, 'canonical_target_indexable', 'fail', 'noindex');
    } elseif ($canonicalTargetCrossDomain) {
        tech_add_check($checks, 'canonical_target_indexable', 'warn', 'cross-domain');
    } else {
        tech_add_check($checks, 'canonical_target_indexable', 'pass', 'ok');
    }
}

tech_add_check($checks, 'robots_meta_noindex', $robotsMetaNoindex ? 'fail' : 'pass', $robotsMetaNoindex ? 'noindex' : 'index');
tech_add_check($checks, 'x_robots_noindex', $xRobotsNoindex ? 'fail' : 'pass', $xRobotsNoindex ? 'noindex' : 'index');

if ($hreflangCount >= 2 && !$hreflangHasXDefault) {
    tech_add_check($checks, 'hreflang_consistency', 'warn', 'x-default missing');
} elseif ($hreflangCount >= 2) {
    tech_add_check($checks, 'hreflang_consistency', 'pass', 'ok');
} else {
    tech_add_check($checks, 'hreflang_consistency', 'pass', $hreflangCount > 0 ? 'single locale' : 'not set');
}

tech_add_check($checks, 'og_core', $ogComplete ? 'pass' : 'warn', $ogComplete ? 'ok' : 'missing');
if ((bool) ($og['image'] ?? false)) {
    if ($ogImageFetchable && $ogImageLooksImage) {
        tech_add_check($checks, 'og_image_fetchable', 'pass', 'ok');
    } elseif ($ogImageFetchable) {
        tech_add_check($checks, 'og_image_fetchable', 'warn', 'non-image content-type');
    } else {
        tech_add_check($checks, 'og_image_fetchable', 'fail', (string) ($ogImageInfo['status_code'] ?? 0));
    }
} else {
    tech_add_check($checks, 'og_image_fetchable', 'warn', 'og:image missing');
}

tech_add_check($checks, 'twitter_core', $twitterComplete ? 'pass' : 'warn', $twitterComplete ? 'ok' : 'missing');
tech_add_check($checks, 'twitter_image_present', $twitterImagePresent ? 'pass' : 'warn', $twitterImagePresent ? 'yes' : 'no');
tech_add_check($checks, 'jsonld_present', $jsonLdCount > 0 ? 'pass' : 'warn', (string) $jsonLdCount);
if ($jsonLdCount === 0) {
    tech_add_check($checks, 'jsonld_valid', 'warn', '0/0');
    tech_add_check($checks, 'jsonld_has_type', 'warn', 'none');
} else {
    tech_add_check($checks, 'jsonld_valid', $jsonLdInvalidCount === 0 ? 'pass' : ($jsonLdValidCount > 0 ? 'warn' : 'fail'), sprintf('%d valid / %d invalid', $jsonLdValidCount, $jsonLdInvalidCount));
    tech_add_check($checks, 'jsonld_has_type', $jsonLdTypedItems > 0 ? 'pass' : 'warn', $jsonLdTypedItems > 0 ? implode(', ', array_slice($jsonLdTypes, 0, 5)) : 'missing @type');
}
tech_add_check($checks, 'viewport_present', $viewportPresent ? 'pass' : 'warn', $viewportPresent ? 'yes' : 'no');
tech_add_check($checks, 'internal_links_count', $internalLinksCount > 0 ? 'pass' : 'warn', (string) $internalLinksCount);

$robotsStatusCode = (int) ($robots['status_code'] ?? 0);
$robotsFound = (bool) ($robots['found'] ?? false);
if ($robotsStatusCode === 0) {
    tech_add_check($checks, 'robots_txt_accessible', 'warn', 'error');
} elseif ($robotsFound) {
    tech_add_check($checks, 'robots_txt_accessible', 'pass', (string) $robotsStatusCode);
} else {
    tech_add_check($checks, 'robots_txt_accessible', 'warn', (string) $robotsStatusCode);
}
tech_add_check($checks, 'robots_txt_blocks_url', $blockedByRobots ? 'fail' : 'pass', $blockedByRobots ? ((string) ($robots['matched_rule'] ?? 'blocked')) : 'allowed');

$counts = ['pass' => 0, 'warn' => 0, 'fail' => 0];
$penalty = 0;
$highImpactChecks = [
    'http_status_200',
    'https',
    'indexable',
    'effective_indexability_conflict',
    'canonical_target_status',
    'canonical_target_indexable',
    'robots_txt_blocks_url',
    'robots_meta_noindex',
    'x_robots_noindex',
];

foreach ($checks as $check) {
    $status = (string) ($check['status'] ?? 'warn');
    if (!isset($counts[$status])) {
        $status = 'warn';
    }
    $counts[$status]++;

    $key = (string) ($check['key'] ?? '');
    $highImpact = in_array($key, $highImpactChecks, true);
    if ($status === 'fail') {
        $penalty += $highImpact ? 11 : 6;
    } elseif ($status === 'warn') {
        $penalty += $highImpact ? 5 : 2;
    }
}

$score = max(0, min(100, 100 - $penalty));

$recommendations = [];
$recoPriorityMap = [
    'fix_http_status' => 'high',
    'enforce_https' => 'high',
    'reduce_redirect_hops' => 'medium',
    'fix_redirect_chain_https' => 'medium',
    'serve_html_content' => 'medium',
    'remove_noindex' => 'high',
    'allow_in_robots' => 'high',
    'add_title' => 'medium',
    'optimize_title_length' => 'low',
    'add_meta_description' => 'medium',
    'optimize_meta_description' => 'low',
    'add_h1' => 'medium',
    'keep_single_h1' => 'low',
    'add_canonical' => 'medium',
    'fix_canonical_domain' => 'high',
    'fix_canonical_target_status' => 'high',
    'fix_canonical_target_indexability' => 'high',
    'align_indexability_signals' => 'high',
    'add_open_graph' => 'low',
    'fix_og_image' => 'medium',
    'add_twitter_tags' => 'low',
    'add_twitter_image' => 'low',
    'add_jsonld' => 'medium',
    'fix_jsonld_validity' => 'medium',
    'add_jsonld_type' => 'medium',
    'add_x_default_hreflang' => 'low',
    'add_viewport' => 'low',
    'publish_robots_txt' => 'medium',
    'improve_internal_links' => 'low',
];

if (!$is2xx) {
    $recommendations[] = 'fix_http_status';
}
if (!$isHttps) {
    $recommendations[] = 'enforce_https';
}
if ($redirectCount >= 2) {
    $recommendations[] = 'reduce_redirect_hops';
}
if (!$redirectHttpsOnly) {
    $recommendations[] = 'fix_redirect_chain_https';
}
if (!$isHtml) {
    $recommendations[] = 'serve_html_content';
}
if ($robotsMetaNoindex || $xRobotsNoindex) {
    $recommendations[] = 'remove_noindex';
}
if ($blockedByRobots) {
    $recommendations[] = 'allow_in_robots';
}
if ($titleLength === 0) {
    $recommendations[] = 'add_title';
} elseif ($titleLength < 30 || $titleLength > 65) {
    $recommendations[] = 'optimize_title_length';
}
if ($metaLength === 0) {
    $recommendations[] = 'add_meta_description';
} elseif ($metaLength < 70 || $metaLength > 160) {
    $recommendations[] = 'optimize_meta_description';
}
if ($h1Count === 0) {
    $recommendations[] = 'add_h1';
} elseif ($h1Count > 1) {
    $recommendations[] = 'keep_single_h1';
}
if ($canonicalUrl === '') {
    $recommendations[] = 'add_canonical';
} else {
    if ($canonicalCrossDomain) {
        $recommendations[] = 'fix_canonical_domain';
    }
    if (!$canonicalTarget2xx) {
        $recommendations[] = 'fix_canonical_target_status';
    }
    if ($canonicalTargetNoindex) {
        $recommendations[] = 'fix_canonical_target_indexability';
    }
}
if ($effectiveIndexabilityConflict) {
    $recommendations[] = 'align_indexability_signals';
}
if (!$ogComplete) {
    $recommendations[] = 'add_open_graph';
}
if ((bool) ($og['image'] ?? false) && (!$ogImageFetchable || !$ogImageLooksImage)) {
    $recommendations[] = 'fix_og_image';
}
if (!$twitterComplete) {
    $recommendations[] = 'add_twitter_tags';
}
if (!$twitterImagePresent) {
    $recommendations[] = 'add_twitter_image';
}
if ($jsonLdCount === 0) {
    $recommendations[] = 'add_jsonld';
} else {
    if ($jsonLdInvalidCount > 0) {
        $recommendations[] = 'fix_jsonld_validity';
    }
    if ($jsonLdTypedItems === 0) {
        $recommendations[] = 'add_jsonld_type';
    }
}
if ($hreflangCount >= 2 && !$hreflangHasXDefault) {
    $recommendations[] = 'add_x_default_hreflang';
}
if (!$viewportPresent) {
    $recommendations[] = 'add_viewport';
}
if (!$robotsFound) {
    $recommendations[] = 'publish_robots_txt';
}
if ($internalLinksCount <= 1) {
    $recommendations[] = 'improve_internal_links';
}

$recommendations = array_values(array_unique($recommendations));

$checklist = ['high' => [], 'medium' => [], 'low' => []];
foreach ($recommendations as $recoKey) {
    $priority = (string) ($recoPriorityMap[$recoKey] ?? 'medium');
    if (!isset($checklist[$priority])) {
        $priority = 'medium';
    }
    $checklist[$priority][] = $recoKey;
}

respond_json([
    'ok' => true,
    'audit' => [
        'url' => $url,
        'final_url' => $finalUrl,
        'status_code' => $statusCode,
        'response_time_ms' => (int) ($fetch['response_time_ms'] ?? 0),
        'content_type' => (string) ($fetch['content_type'] ?? ''),
        'redirect_count' => $redirectCount,
        'redirect_chain' => $redirectChain,
        'indexable' => $indexable,
        'score' => $score,
        'counts' => $counts,
        'checks' => $checks,
        'metrics' => [
            'title' => (string) ($signals['title'] ?? ''),
            'title_length' => $titleLength,
            'meta_description_length' => $metaLength,
            'h1_count' => $h1Count,
            'canonical_url' => $canonicalUrl,
            'canonical_count' => $canonicalCount,
            'canonical_cross_domain' => $canonicalCrossDomain,
            'canonical_target' => $canonicalTarget,
            'robots_meta' => (string) ($signals['robots_meta'] ?? ''),
            'x_robots_tag' => (string) ($headers['x-robots-tag'] ?? ''),
            'hreflang_count' => $hreflangCount,
            'hreflang_has_x_default' => $hreflangHasXDefault,
            'og_complete' => $ogComplete,
            'og_image' => $ogImageInfo,
            'twitter_complete' => $twitterComplete,
            'twitter_image_present' => $twitterImagePresent,
            'json_ld_count' => $jsonLdCount,
            'json_ld_valid_count' => $jsonLdValidCount,
            'json_ld_invalid_count' => $jsonLdInvalidCount,
            'json_ld_types' => $jsonLdTypes,
            'json_ld_typed_items' => $jsonLdTypedItems,
            'viewport_present' => $viewportPresent,
            'internal_links_count' => $internalLinksCount,
            'effective_indexability_conflict' => $effectiveIndexabilityConflict,
            'effective_indexability_detail' => $effectiveIndexabilityDetail,
        ],
        'robots' => [
            'url' => (string) ($robots['url'] ?? ''),
            'status_code' => (int) ($robots['status_code'] ?? 0),
            'found' => (bool) ($robots['found'] ?? false),
            'blocked' => $blockedByRobots,
            'matched_rule' => (string) ($robots['matched_rule'] ?? ''),
            'error' => (string) ($robots['error'] ?? ''),
        ],
        'recommendations' => $recommendations,
        'checklist' => $checklist,
    ],
]);
