<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('geo_audit_run', $ip, 18, 600);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit audit GEO atteint. Reessaye plus tard.',
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

function geo_strlen(string $value): int
{
    if (function_exists('mb_strlen')) {
        return (int) mb_strlen($value, 'UTF-8');
    }
    return strlen($value);
}

function geo_normalize_space(string $value): string
{
    return trim((string) preg_replace('/\s+/u', ' ', $value));
}

function geo_parse_header_block(string $rawHeaders): array
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

function geo_parse_headers_with_intermediate(string $rawHeaders): array
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
        $headers = geo_parse_header_block($block);
        $parsed[] = [
            'status_line' => $statusLine,
            'headers' => $headers,
        ];
    }
    return $parsed;
}

function geo_resolve_url(string $baseUrl, string $target): ?string
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

function geo_fetch_once(string $url, int $timeout): array
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
        CURLOPT_USERAGENT => 'SEO-Sitemap-Tool-GEOAudit/1.0',
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

    $headerBlocks = geo_parse_headers_with_intermediate($headerChunk);
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

function geo_fetch_with_redirects(string $url, int $timeout, int $maxRedirects): array
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

        $fetch = geo_fetch_once($currentUrl, $timeout);
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
            $nextUrl = geo_resolve_url($currentUrl, $location);
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

function geo_extract_jsonld_blocks(string $html): array
{
    $blocks = [];
    if (preg_match_all('/<script[^>]*type=["\']application\/ld\+json["\'][^>]*>(.*?)<\/script>/is', $html, $matches)) {
        foreach (($matches[1] ?? []) as $raw) {
            if (!is_string($raw)) {
                continue;
            }
            $candidate = trim($raw);
            if ($candidate !== '') {
                $blocks[] = $candidate;
            }
        }
    }
    return $blocks;
}

function geo_collect_jsonld_objects(mixed $decoded, array &$objects): void
{
    if (!is_array($decoded)) {
        return;
    }
    $isAssoc = array_keys($decoded) !== range(0, count($decoded) - 1);
    if ($isAssoc) {
        $objects[] = $decoded;
        if (isset($decoded['@graph']) && is_array($decoded['@graph'])) {
            foreach ($decoded['@graph'] as $item) {
                geo_collect_jsonld_objects($item, $objects);
            }
        }
        return;
    }
    foreach ($decoded as $item) {
        geo_collect_jsonld_objects($item, $objects);
    }
}

function geo_extract_jsonld_types(array $objects): array
{
    $types = [];
    foreach ($objects as $obj) {
        $value = $obj['@type'] ?? null;
        if (is_string($value)) {
            $type = trim($value);
            if ($type !== '') {
                $types[$type] = true;
            }
            continue;
        }
        if (is_array($value)) {
            foreach ($value as $entry) {
                if (!is_string($entry)) {
                    continue;
                }
                $type = trim($entry);
                if ($type !== '') {
                    $types[$type] = true;
                }
            }
        }
    }
    $keys = array_keys($types);
    sort($keys);
    return $keys;
}

function geo_pick_jsonld_date(array $objects, string $field): string
{
    foreach ($objects as $obj) {
        $candidate = trim((string) ($obj[$field] ?? ''));
        if ($candidate !== '') {
            return $candidate;
        }
    }
    return '';
}

function geo_status_factor(string $status): float
{
    $raw = strtolower(trim($status));
    if ($raw === 'pass') return 1.0;
    if ($raw === 'warn') return 0.55;
    return 0.0;
}

$fetch = geo_fetch_with_redirects($url, $timeout, $maxRedirects);
if (empty($fetch['ok'])) {
    respond_json(['error' => (string) ($fetch['error'] ?? 'Erreur audit GEO')], 502);
}

$finalUrl = (string) ($fetch['final_url'] ?? $url);
$statusCode = (int) ($fetch['status_code'] ?? 0);
$responseMs = (int) ($fetch['response_time_ms'] ?? 0);
$contentType = strtolower((string) ($fetch['content_type'] ?? ''));
$headers = is_array($fetch['headers'] ?? null) ? $fetch['headers'] : [];
$body = (string) ($fetch['body'] ?? '');
$redirectCount = (int) ($fetch['redirect_count'] ?? 0);
$redirectChain = is_array($fetch['redirect_chain'] ?? null) ? $fetch['redirect_chain'] : [];

$metaRobots = '';
$xRobots = strtolower((string) ($headers['x-robots-tag'] ?? ''));
$isHtml = str_contains($contentType, 'text/html') || str_contains($contentType, 'application/xhtml+xml');

$title = '';
$metaDescription = '';
$wordCount = 0;
$paragraphCount = 0;
$firstParagraphLen = 0;
$h1Count = 0;
$h2Count = 0;
$h3Count = 0;
$listCount = 0;
$tableCount = 0;
$internalLinksCount = 0;
$externalLinksCount = 0;
$aboutContactLinks = 0;
$questionHeadingsCount = 0;
$faqDomBlocks = 0;
$authorSignals = 0;
$publishedDate = '';
$modifiedDate = '';

$jsonLdBlocks = geo_extract_jsonld_blocks($body);
$jsonLdObjects = [];
foreach ($jsonLdBlocks as $block) {
    $decoded = json_decode($block, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        continue;
    }
    geo_collect_jsonld_objects($decoded, $jsonLdObjects);
}
$jsonLdTypes = geo_extract_jsonld_types($jsonLdObjects);
$hasOrganization = in_array('Organization', $jsonLdTypes, true) || in_array('LocalBusiness', $jsonLdTypes, true);
$hasFaqMarkup = in_array('FAQPage', $jsonLdTypes, true) || in_array('QAPage', $jsonLdTypes, true);

if ($isHtml && class_exists('DOMDocument')) {
    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    @$dom->loadHTML($body, LIBXML_NOWARNING | LIBXML_NOERROR | LIBXML_NONET);
    $xpath = new DOMXPath($dom);

    $titleNode = $xpath->query('//title');
    if ($titleNode !== false && $titleNode->length > 0) {
        $title = geo_normalize_space((string) $titleNode->item(0)->textContent);
    }

    $metaDescNode = $xpath->query('//meta[translate(@name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="description"]/@content');
    if ($metaDescNode !== false && $metaDescNode->length > 0) {
        $metaDescription = geo_normalize_space((string) $metaDescNode->item(0)->textContent);
    }

    $metaRobotsNode = $xpath->query('//meta[translate(@name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="robots"]/@content');
    if ($metaRobotsNode !== false && $metaRobotsNode->length > 0) {
        $metaRobots = strtolower(geo_normalize_space((string) $metaRobotsNode->item(0)->textContent));
    }

    $metaPublished = $xpath->query('//meta[@property="article:published_time"]/@content');
    if ($metaPublished !== false && $metaPublished->length > 0) {
        $publishedDate = trim((string) $metaPublished->item(0)->textContent);
    }

    $metaModified = $xpath->query('//meta[@property="article:modified_time"]/@content');
    if ($metaModified !== false && $metaModified->length > 0) {
        $modifiedDate = trim((string) $metaModified->item(0)->textContent);
    }

    $h1Count = (int) ($xpath->query('//h1')->length ?? 0);
    $h2Count = (int) ($xpath->query('//h2')->length ?? 0);
    $h3Count = (int) ($xpath->query('//h3')->length ?? 0);
    $listCount = (int) (($xpath->query('//ul')->length ?? 0) + ($xpath->query('//ol')->length ?? 0));
    $tableCount = (int) ($xpath->query('//table')->length ?? 0);

    $paragraphs = $xpath->query('//p');
    if ($paragraphs !== false) {
        $paragraphCount = (int) $paragraphs->length;
        foreach ($paragraphs as $idx => $paragraph) {
            $text = geo_normalize_space((string) $paragraph->textContent);
            if ($text === '') {
                continue;
            }
            if ($idx === 0) {
                $firstParagraphLen = geo_strlen($text);
            }
            $words = preg_split('/\s+/u', $text) ?: [];
            $wordCount += count(array_filter($words, static fn($w): bool => trim((string) $w) !== ''));
        }
    }

    $headings = $xpath->query('//h2|//h3|//h4');
    if ($headings !== false) {
        foreach ($headings as $heading) {
            $text = strtolower(geo_normalize_space((string) $heading->textContent));
            if ($text === '') {
                continue;
            }
            if (str_contains($text, '?') || preg_match('/\b(comment|pourquoi|quoi|quand|how|what|why|when)\b/u', $text)) {
                $questionHeadingsCount++;
            }
        }
    }

    $faqDomBlocks = (int) ($xpath->query('//*[contains(translate(@class, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "faq")]')->length ?? 0);
    $faqDomBlocks += (int) ($xpath->query('//*[contains(translate(@class, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "question")]')->length ?? 0);
    $faqDomBlocks += (int) ($xpath->query('//*[contains(translate(@class, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "answer")]')->length ?? 0);

    $authorMeta = $xpath->query('//meta[translate(@name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="author"]/@content');
    if ($authorMeta !== false && $authorMeta->length > 0 && trim((string) $authorMeta->item(0)->textContent) !== '') {
        $authorSignals++;
    }
    $authorEls = $xpath->query('//*[contains(translate(@class, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "author") or contains(translate(@class, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "byline")]');
    if ($authorEls !== false && $authorEls->length > 0) {
        $authorSignals += (int) min(2, $authorEls->length);
    }

    $finalHost = strtolower((string) parse_url($finalUrl, PHP_URL_HOST));
    $anchors = $xpath->query('//a[@href]');
    if ($anchors !== false) {
        foreach ($anchors as $a) {
            $href = trim((string) $a->getAttribute('href'));
            if ($href === '' || str_starts_with($href, '#') || str_starts_with(strtolower($href), 'javascript:')) {
                continue;
            }
            $resolved = geo_resolve_url($finalUrl, $href);
            if (!is_string($resolved) || $resolved === '') {
                continue;
            }
            $host = strtolower((string) parse_url($resolved, PHP_URL_HOST));
            $path = strtolower((string) parse_url($resolved, PHP_URL_PATH));
            if ($host !== '' && $finalHost !== '' && $host === $finalHost) {
                $internalLinksCount++;
            } else {
                $externalLinksCount++;
            }
            if (preg_match('~/(about|a-propos|contact|mentions-legales)~', $path)) {
                $aboutContactLinks++;
            }
        }
    }
    libxml_clear_errors();
}

if ($publishedDate === '') {
    $publishedDate = geo_pick_jsonld_date($jsonLdObjects, 'datePublished');
}
if ($modifiedDate === '') {
    $modifiedDate = geo_pick_jsonld_date($jsonLdObjects, 'dateModified');
}
if ($modifiedDate === '') {
    $modifiedDate = geo_pick_jsonld_date($jsonLdObjects, 'dateCreated');
}

$indexable = !(str_contains($metaRobots, 'noindex') || str_contains($xRobots, 'noindex'));
$freshnessDays = null;
if ($modifiedDate !== '') {
    $ts = strtotime($modifiedDate);
    if ($ts !== false && $ts > 0) {
        $freshnessDays = (int) floor((time() - $ts) / 86400);
    }
}

$checks = [];
$addCheck = static function (string $key, string $status, string $value) use (&$checks): void {
    $checks[] = ['key' => $key, 'status' => $status, 'value' => $value];
};

$addCheck('geo_http_status_2xx', ($statusCode >= 200 && $statusCode < 300) ? 'pass' : 'fail', (string) $statusCode);
$addCheck('geo_html_content_type', $isHtml ? 'pass' : 'fail', $contentType !== '' ? $contentType : '-');
$addCheck('geo_indexable', $indexable ? 'pass' : 'fail', $indexable ? 'indexable' : 'noindex signal');

$structuredStatus = count($jsonLdTypes) >= 2 ? 'pass' : (count($jsonLdTypes) === 1 ? 'warn' : 'fail');
$addCheck('geo_structured_data', $structuredStatus, count($jsonLdTypes) > 0 ? implode(', ', array_slice($jsonLdTypes, 0, 6)) : 'none');

$orgStatus = ($hasOrganization || $aboutContactLinks > 0) ? 'pass' : 'fail';
$addCheck('geo_organization_entity', $orgStatus, $hasOrganization ? 'schema Organization' : 'missing Organization/entity signals');

$authorStatus = $authorSignals >= 2 ? 'pass' : ($authorSignals === 1 ? 'warn' : 'fail');
$addCheck('geo_author_signal', $authorStatus, (string) $authorSignals);

$dateStatus = ($publishedDate !== '' && $modifiedDate !== '') ? 'pass' : (($publishedDate !== '' || $modifiedDate !== '') ? 'warn' : 'fail');
$addCheck('geo_date_metadata', $dateStatus, trim($publishedDate . ' / ' . $modifiedDate, ' /') ?: 'none');

$freshnessStatus = 'warn';
$freshnessValue = 'unknown';
if (is_int($freshnessDays)) {
    $freshnessValue = (string) $freshnessDays . 'd';
    if ($freshnessDays <= 365) {
        $freshnessStatus = 'pass';
    } elseif ($freshnessDays > 730) {
        $freshnessStatus = 'fail';
    }
}
$addCheck('geo_freshness', $freshnessStatus, $freshnessValue);

$qaSignals = ($questionHeadingsCount > 0) ? 1 : 0;
if ($firstParagraphLen >= 40 && $firstParagraphLen <= 320) {
    $qaSignals++;
}
if ($paragraphCount >= 3) {
    $qaSignals++;
}
$qaStatus = $qaSignals >= 2 ? 'pass' : ($qaSignals === 1 ? 'warn' : 'fail');
$addCheck('geo_qa_format', $qaStatus, sprintf('q:%d p:%d intro:%d', $questionHeadingsCount, $paragraphCount, $firstParagraphLen));

$faqSignals = ($hasFaqMarkup ? 1 : 0) + ($faqDomBlocks > 0 ? 1 : 0);
$faqStatus = $faqSignals >= 1 ? 'pass' : 'warn';
$addCheck('geo_faq_markup', $faqStatus, $hasFaqMarkup ? 'FAQPage/QAPage' : (string) $faqDomBlocks . ' faq blocks');

$depthStatus = $wordCount >= 350 ? 'pass' : ($wordCount >= 180 ? 'warn' : 'fail');
$addCheck('geo_content_depth', $depthStatus, (string) $wordCount . ' words');

$internalStatus = $internalLinksCount >= 5 ? 'pass' : ($internalLinksCount >= 2 ? 'warn' : 'fail');
$addCheck('geo_internal_links', $internalStatus, (string) $internalLinksCount);

$citationsStatus = $externalLinksCount >= 2 ? 'pass' : ($externalLinksCount >= 1 ? 'warn' : 'fail');
$addCheck('geo_citations_external', $citationsStatus, (string) $externalLinksCount);

$blocksStatus = ($listCount + $tableCount) >= 1 ? 'pass' : 'warn';
$addCheck('geo_list_table_blocks', $blocksStatus, sprintf('list:%d table:%d', $listCount, $tableCount));

$weights = [
    'geo_http_status_2xx' => 12,
    'geo_html_content_type' => 8,
    'geo_indexable' => 10,
    'geo_structured_data' => 12,
    'geo_organization_entity' => 9,
    'geo_author_signal' => 7,
    'geo_date_metadata' => 8,
    'geo_freshness' => 8,
    'geo_qa_format' => 9,
    'geo_faq_markup' => 5,
    'geo_content_depth' => 5,
    'geo_internal_links' => 3,
    'geo_citations_external' => 2,
    'geo_list_table_blocks' => 2,
];

$scoreRaw = 0.0;
$counts = ['pass' => 0, 'warn' => 0, 'fail' => 0];
foreach ($checks as $check) {
    $status = strtolower((string) ($check['status'] ?? 'warn'));
    if (!isset($counts[$status])) {
        $status = 'warn';
    }
    $counts[$status]++;
    $weight = (float) ($weights[(string) ($check['key'] ?? '')] ?? 0.0);
    $scoreRaw += $weight * geo_status_factor($status);
}
$score = (int) max(0, min(100, round($scoreRaw)));

$recommendations = [];
$pushReco = static function (string $key) use (&$recommendations): void {
    if (!in_array($key, $recommendations, true)) {
        $recommendations[] = $key;
    }
};
$statusByKey = [];
foreach ($checks as $check) {
    $statusByKey[(string) $check['key']] = strtolower((string) ($check['status'] ?? 'warn'));
}
if (($statusByKey['geo_structured_data'] ?? 'warn') !== 'pass') $pushReco('geo_reco_add_structured_data');
if (($statusByKey['geo_organization_entity'] ?? 'warn') !== 'pass') $pushReco('geo_reco_add_organization_entity');
if (($statusByKey['geo_author_signal'] ?? 'warn') !== 'pass') $pushReco('geo_reco_add_author_signals');
if (($statusByKey['geo_date_metadata'] ?? 'warn') !== 'pass') $pushReco('geo_reco_add_dates');
if (($statusByKey['geo_freshness'] ?? 'warn') === 'fail') $pushReco('geo_reco_refresh_content');
if (($statusByKey['geo_qa_format'] ?? 'warn') !== 'pass') $pushReco('geo_reco_improve_qa_format');
if (($statusByKey['geo_faq_markup'] ?? 'warn') !== 'pass') $pushReco('geo_reco_add_faq_markup');
if (($statusByKey['geo_content_depth'] ?? 'warn') !== 'pass') $pushReco('geo_reco_deepen_content');
if (($statusByKey['geo_internal_links'] ?? 'warn') !== 'pass') $pushReco('geo_reco_improve_internal_links');
if (($statusByKey['geo_citations_external'] ?? 'warn') !== 'pass') $pushReco('geo_reco_add_external_citations');

$checklist = ['high' => [], 'medium' => [], 'low' => []];
$highKeys = ['geo_http_status_2xx', 'geo_html_content_type', 'geo_indexable', 'geo_structured_data', 'geo_organization_entity'];
foreach ($checks as $check) {
    $key = (string) ($check['key'] ?? '');
    $status = strtolower((string) ($check['status'] ?? 'warn'));
    if ($status === 'pass') {
        continue;
    }
    if ($status === 'fail' && in_array($key, $highKeys, true)) {
        $checklist['high'][] = $key;
    } elseif ($status === 'fail') {
        $checklist['medium'][] = $key;
    } else {
        $checklist['low'][] = $key;
    }
}

$payload = [
    'ok' => true,
    'audit' => [
        'url' => $url,
        'final_url' => $finalUrl,
        'status_code' => $statusCode,
        'response_time_ms' => $responseMs,
        'content_type' => $contentType,
        'redirect_count' => $redirectCount,
        'redirect_chain' => $redirectChain,
        'indexable' => $indexable,
        'score' => $score,
        'counts' => $counts,
        'checks' => $checks,
        'recommendations' => $recommendations,
        'checklist' => $checklist,
        'metrics' => [
            'title' => $title,
            'meta_description' => $metaDescription,
            'h1_count' => $h1Count,
            'h2_count' => $h2Count,
            'h3_count' => $h3Count,
            'word_count' => $wordCount,
            'paragraph_count' => $paragraphCount,
            'internal_links_count' => $internalLinksCount,
            'external_links_count' => $externalLinksCount,
            'structured_types' => $jsonLdTypes,
            'published_date' => $publishedDate,
            'modified_date' => $modifiedDate,
            'freshness_days' => $freshnessDays,
            'question_headings_count' => $questionHeadingsCount,
            'faq_dom_blocks' => $faqDomBlocks,
        ],
    ],
];

respond_json($payload, 200);
