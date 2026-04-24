<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('images_audit_run', $ip, 18, 600);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit audit images atteint. Reessaye plus tard.',
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

function img_parse_header_block(string $rawHeaders): array
{
    $headers = [];
    $lines = preg_split('/\r\n|\n|\r/', trim($rawHeaders)) ?: [];
    foreach ($lines as $line) {
        if (!is_string($line) || !str_contains($line, ':')) continue;
        [$n, $v] = explode(':', $line, 2);
        $k = strtolower(trim($n));
        if ($k === '') continue;
        $headers[$k] ??= [];
        $headers[$k][] = trim((string) $v);
    }
    return $headers;
}

function img_fetch(string $url, int $timeout): array
{
    $parsed = parse_url($url);
    if (!is_array($parsed)) return ['ok' => false, 'error' => 'URL invalide.'];
    $host = strtolower((string) ($parsed['host'] ?? ''));
    $scheme = strtolower((string) ($parsed['scheme'] ?? 'https'));
    if ($host === '' || !in_array($scheme, ['http', 'https'], true)) {
        return ['ok' => false, 'error' => 'URL invalide.'];
    }
    $port = isset($parsed['port']) ? (int) $parsed['port'] : ($scheme === 'http' ? 80 : 443);

    $resolveError = '';
    $resolvedIp = resolve_public_ip_for_host($host, $resolveError);
    if (!is_string($resolvedIp) || $resolvedIp === '') {
        return ['ok' => false, 'error' => $resolveError !== '' ? $resolveError : 'Resolution DNS invalide.'];
    }

    $ch = curl_init($url);
    if ($ch === false) return ['ok' => false, 'error' => 'Impossible d initialiser cURL.'];

    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 8,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_USERAGENT => 'SEO-Sitemap-Tool-ImagesAudit/1.0',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
        CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $resolvedIp],
        CURLOPT_HTTPHEADER => [
            'Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.7',
        ],
    ];
    if (defined('CURLOPT_PROTOCOLS')) {
        $opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        $opts[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
    }
    curl_setopt_array($ch, $opts);

    $raw = curl_exec($ch);
    $errno = curl_errno($ch);
    $error = curl_error($ch);
    $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $totalTime = (float) curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    $contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $finalUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $redirectCount = (int) curl_getinfo($ch, CURLINFO_REDIRECT_COUNT);
    curl_close($ch);

    if (!is_string($raw) || $errno !== 0) {
        return ['ok' => false, 'error' => $error !== '' ? $error : 'Erreur reseau.'];
    }

    $finalValidationError = '';
    if (!validate_public_url($finalUrl !== '' ? $finalUrl : $url, $finalValidationError)) {
        return ['ok' => false, 'error' => $finalValidationError];
    }

    $body = (string) substr($raw, max(0, $headerSize));

    return [
        'ok' => true,
        'status_code' => $statusCode,
        'response_time_ms' => (int) round($totalTime * 1000),
        'content_type' => $contentType,
        'body' => $body,
        'final_url' => $finalUrl !== '' ? $finalUrl : $url,
        'redirect_count' => $redirectCount,
    ];
}

function img_status_factor(string $status): float
{
    $raw = strtolower(trim($status));
    if ($raw === 'pass') return 1.0;
    if ($raw === 'warn') return 0.55;
    return 0.0;
}

function img_extension(string $url): string
{
    $path = (string) parse_url($url, PHP_URL_PATH);
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    return $ext;
}

$fetch = img_fetch($url, $timeout);
if (empty($fetch['ok'])) {
    respond_json(['error' => (string) ($fetch['error'] ?? 'Erreur audit images')], 502);
}

$finalUrl = (string) $fetch['final_url'];
$statusCode = (int) $fetch['status_code'];
$responseMs = (int) $fetch['response_time_ms'];
$contentType = strtolower((string) $fetch['content_type']);
$body = (string) $fetch['body'];
$redirectCount = (int) $fetch['redirect_count'];

$isHtml = str_contains($contentType, 'text/html') || str_contains($contentType, 'application/xhtml+xml');

$totalImages = 0;
$withAlt = 0;
$withEmptyAlt = 0; // decorative, also valid
$withoutAlt = 0;
$withDimensions = 0;
$withLazy = 0;
$withSrcset = 0;
$inPicture = 0;
$formats = ['webp' => 0, 'avif' => 0, 'jpg' => 0, 'png' => 0, 'gif' => 0, 'svg' => 0, 'other' => 0];
$sampleMissingAlt = [];
$sampleMissingDims = [];

if ($isHtml && class_exists('DOMDocument')) {
    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    @$dom->loadHTML($body, LIBXML_NOWARNING | LIBXML_NOERROR | LIBXML_NONET);
    $xpath = new DOMXPath($dom);

    $imgs = $xpath->query('//img');
    if ($imgs instanceof DOMNodeList) {
        foreach ($imgs as $index => $img) {
            if (!($img instanceof DOMElement)) continue;
            $totalImages++;

            $hasAltAttr = $img->hasAttribute('alt');
            $altRaw = $hasAltAttr ? trim((string) $img->getAttribute('alt')) : '';
            if (!$hasAltAttr) {
                $withoutAlt++;
                if (count($sampleMissingAlt) < 10) $sampleMissingAlt[] = trim((string) $img->getAttribute('src'));
            } elseif ($altRaw === '') {
                $withEmptyAlt++;
            } else {
                $withAlt++;
            }

            $hasW = $img->hasAttribute('width');
            $hasH = $img->hasAttribute('height');
            if ($hasW && $hasH) {
                $withDimensions++;
            } else if (count($sampleMissingDims) < 10) {
                $sampleMissingDims[] = trim((string) $img->getAttribute('src'));
            }

            $loading = strtolower((string) $img->getAttribute('loading'));
            if ($loading === 'lazy') $withLazy++;

            if ($img->hasAttribute('srcset')) $withSrcset++;

            $parent = $img->parentNode;
            while ($parent instanceof DOMElement) {
                if (strtolower($parent->nodeName) === 'picture') { $inPicture++; break; }
                $parent = $parent->parentNode;
            }

            $src = trim((string) $img->getAttribute('src'));
            $ext = img_extension($src);
            if ($ext === 'webp') $formats['webp']++;
            elseif ($ext === 'avif') $formats['avif']++;
            elseif ($ext === 'jpg' || $ext === 'jpeg') $formats['jpg']++;
            elseif ($ext === 'png') $formats['png']++;
            elseif ($ext === 'gif') $formats['gif']++;
            elseif ($ext === 'svg') $formats['svg']++;
            else $formats['other']++;
        }
    }

    // Also count <source> inside <picture> with modern type/src for counting purposes
}

$checks = [];
$recommendations = [];
$checklist = ['high' => [], 'medium' => [], 'low' => []];

function img_add_check(array &$checks, string $key, string $status, int $weight, string $value): void
{
    $checks[] = ['key' => $key, 'status' => $status, 'weight' => $weight, 'value' => $value];
}

if ($totalImages === 0) {
    img_add_check($checks, 'img_presence', 'warn', 1, 'no-images');
} else {
    // img_alt: all images should have alt (empty alt is OK for decorative)
    $altCovered = $withAlt + $withEmptyAlt;
    $altPct = (int) round($altCovered / $totalImages * 100);
    $altStatus = $altPct === 100 ? 'pass' : ($altPct >= 90 ? 'warn' : 'fail');
    img_add_check($checks, 'img_alt_coverage', $altStatus, 8, $altPct . '% (' . $withoutAlt . ' sans alt)');

    // img_dimensions
    $dimsPct = (int) round($withDimensions / $totalImages * 100);
    $dimsStatus = $dimsPct >= 95 ? 'pass' : ($dimsPct >= 70 ? 'warn' : 'fail');
    img_add_check($checks, 'img_dimensions', $dimsStatus, 6, $dimsPct . '% (' . ($totalImages - $withDimensions) . ' sans width/height)');

    // img_lazy (excluding above-the-fold, hard to detect — just report ratio)
    // Heuristic: if there are more than 3 images and less than half use lazy, warn
    if ($totalImages > 3) {
        $lazyPct = (int) round($withLazy / $totalImages * 100);
        $lazyStatus = $lazyPct >= 50 ? 'pass' : ($lazyPct > 0 ? 'warn' : 'fail');
        img_add_check($checks, 'img_lazy_loading', $lazyStatus, 4, $lazyPct . '%');
    }

    // img_modern_format
    $modern = $formats['webp'] + $formats['avif'];
    $legacy = $formats['jpg'] + $formats['png'];
    $rasterTotal = $modern + $legacy;
    if ($rasterTotal > 0) {
        $modernPct = (int) round($modern / $rasterTotal * 100);
        $modStatus = $modernPct >= 70 ? 'pass' : ($modernPct >= 30 ? 'warn' : 'fail');
        img_add_check($checks, 'img_modern_format', $modStatus, 5, $modernPct . '% webp/avif');
    }

    // img_responsive
    $responsive = $withSrcset + $inPicture;
    $respPct = (int) round($responsive / $totalImages * 100);
    $respStatus = $respPct >= 50 ? 'pass' : ($respPct >= 15 ? 'warn' : 'fail');
    img_add_check($checks, 'img_responsive', $respStatus, 4, $respPct . '% (srcset ou picture)');
}

// Compute score
$totalWeight = 0;
$earnedWeight = 0.0;
foreach ($checks as $c) {
    $totalWeight += (int) $c['weight'];
    $earnedWeight += (float) $c['weight'] * img_status_factor((string) $c['status']);
}
$score = $totalWeight > 0 ? (int) round($earnedWeight / $totalWeight * 100) : 0;

// Reco mapping
$RECOS = [
    'img_alt_coverage' => ['high', 'images_reco_alt'],
    'img_dimensions' => ['medium', 'images_reco_dimensions'],
    'img_lazy_loading' => ['low', 'images_reco_lazy'],
    'img_modern_format' => ['medium', 'images_reco_modern_format'],
    'img_responsive' => ['low', 'images_reco_responsive'],
    'img_presence' => ['low', 'images_reco_presence'],
];
foreach ($checks as $c) {
    if ($c['status'] === 'pass') continue;
    $info = $RECOS[$c['key']] ?? null;
    if ($info === null) continue;
    [$bucket, $recoKey] = $info;
    $recommendations[] = $recoKey;
    $checklist[$bucket][] = $recoKey;
}

$kpis = [
    'score' => $score,
    'total_images' => $totalImages,
    'without_alt' => $withoutAlt,
    'without_dimensions' => $totalImages > 0 ? ($totalImages - $withDimensions) : 0,
    'modern_format_pct' => $totalImages > 0 && ($formats['webp'] + $formats['avif'] + $formats['jpg'] + $formats['png']) > 0
        ? (int) round(($formats['webp'] + $formats['avif']) / ($formats['webp'] + $formats['avif'] + $formats['jpg'] + $formats['png']) * 100)
        : 0,
];

respond_json([
    'ok' => true,
    'audit' => [
        'url' => $url,
        'final_url' => $finalUrl,
        'status_code' => $statusCode,
        'response_time_ms' => $responseMs,
        'content_type' => $contentType,
        'redirect_count' => $redirectCount,
        'score' => $score,
        'kpis' => $kpis,
        'checks' => $checks,
        'recommendations' => $recommendations,
        'checklist' => $checklist,
        'metrics' => [
            'total_images' => $totalImages,
            'with_alt' => $withAlt,
            'with_empty_alt' => $withEmptyAlt,
            'without_alt' => $withoutAlt,
            'with_dimensions' => $withDimensions,
            'with_lazy' => $withLazy,
            'with_srcset' => $withSrcset,
            'in_picture' => $inPicture,
            'formats' => $formats,
            'sample_missing_alt' => $sampleMissingAlt,
            'sample_missing_dims' => $sampleMissingDims,
        ],
    ],
], 200);
