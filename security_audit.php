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
$limit = enforce_rate_limit('security_audit_run', $ip, 18, 600);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit audit securite atteint. Reessaye plus tard.',
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

scan_history_log('security_audit', $url);

$timeout = clamp_int($input['timeout'] ?? 12, 3, 30, 12);
$maxRedirects = 8;

if (!function_exists('curl_init')) {
    respond_json(['error' => 'cURL est indisponible sur cet hebergement.'], 500);
}

function sec_parse_header_block(string $rawHeaders): array
{
    $headers = [];
    $lines = preg_split('/\r\n|\n|\r/', trim($rawHeaders)) ?: [];
    foreach ($lines as $line) {
        if (!is_string($line) || trim($line) === '' || !str_contains($line, ':')) {
            continue;
        }
        [$name, $value] = explode(':', $line, 2);
        $key = strtolower(trim($name));
        if ($key === '') continue;
        $headers[$key] ??= [];
        $headers[$key][] = trim((string) $value);
    }
    return $headers;
}

function sec_fetch_once(string $url, int $timeout): array
{
    $parsed = parse_url($url);
    if (!is_array($parsed)) return ['ok' => false, 'error' => 'URL invalide.'];
    $host = strtolower((string) ($parsed['host'] ?? ''));
    $scheme = strtolower((string) ($parsed['scheme'] ?? 'https'));
    if ($host === '' || !in_array($scheme, ['http', 'https'], true)) {
        return ['ok' => false, 'error' => 'URL invalide.'];
    }
    $port = isset($parsed['port']) ? (int) $parsed['port'] : ($scheme === 'http' ? 80 : 443);
    if ($port < 1 || $port > 65535) return ['ok' => false, 'error' => 'Port invalide.'];

    $resolveError = '';
    $resolvedIp = resolve_public_ip_for_host($host, $resolveError);
    if (!is_string($resolvedIp) || $resolvedIp === '') {
        return ['ok' => false, 'error' => $resolveError !== '' ? $resolveError : 'Resolution DNS invalide.'];
    }

    $ch = curl_init($url);
    if ($ch === false) return ['ok' => false, 'error' => 'Impossible d initialiser cURL.'];

    $curlOptions = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 0,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_USERAGENT => 'SEO-Sitemap-Tool-SecurityAudit/1.0',
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
        $curlOptions[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
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
        return ['ok' => false, 'error' => $error !== '' ? $error : 'Erreur reseau lors du fetch.'];
    }

    $headerChunk = substr($raw, 0, max(0, $headerSize));
    $body = (string) substr($raw, max(0, $headerSize));

    $blocks = preg_split('/\r\n\r\n|\n\n/', trim((string) $headerChunk)) ?: [];
    $lastBlock = (string) end($blocks);
    $headers = sec_parse_header_block($lastBlock);

    $flat = [];
    foreach ($headers as $name => $values) {
        $flat[$name] = is_array($values) ? implode(', ', $values) : (string) $values;
    }

    $setCookies = $headers['set-cookie'] ?? [];
    if (!is_array($setCookies)) $setCookies = [(string) $setCookies];

    return [
        'ok' => true,
        'status_code' => $statusCode,
        'response_time_ms' => (int) round($totalTime * 1000),
        'content_type' => $contentType,
        'headers' => $flat,
        'set_cookies' => $setCookies,
        'body' => $body,
        'location' => (string) ($flat['location'] ?? ''),
    ];
}

function sec_resolve_url(string $baseUrl, string $target): ?string
{
    $target = trim($target);
    if ($target === '') return null;
    if (preg_match('/^https?:\/\//i', $target)) return $target;
    if (str_starts_with($target, '//')) {
        $scheme = (string) parse_url($baseUrl, PHP_URL_SCHEME);
        return $scheme !== '' ? $scheme . ':' . $target : null;
    }
    $base = parse_url($baseUrl);
    if (!is_array($base)) return null;
    $scheme = strtolower((string) ($base['scheme'] ?? ''));
    $host = (string) ($base['host'] ?? '');
    if ($scheme === '' || $host === '') return null;
    $port = isset($base['port']) ? ':' . (int) $base['port'] : '';
    if (str_starts_with($target, '/')) return $scheme . '://' . $host . $port . $target;
    return $scheme . '://' . $host . $port . '/' . ltrim($target, '/');
}

function sec_fetch_with_redirects(string $url, int $timeout, int $maxRedirects): array
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

        $fetch = sec_fetch_once($currentUrl, $timeout);
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
            $next = sec_resolve_url($currentUrl, $location);
            if (!is_string($next) || $next === '') {
                return ['ok' => false, 'error' => 'URL de redirection invalide.', 'redirect_chain' => $chain];
            }
            $validationError = '';
            if (!validate_public_url($next, $validationError)) {
                return ['ok' => false, 'error' => 'Redirection bloquee: ' . $validationError, 'redirect_chain' => $chain];
            }
            $currentUrl = $next;
            $redirectCount++;
            continue;
        }

        if ($isRedirect && $redirectCount >= $maxRedirects) {
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
            'set_cookies' => is_array($fetch['set_cookies'] ?? null) ? $fetch['set_cookies'] : [],
            'body' => (string) ($fetch['body'] ?? ''),
            'redirect_chain' => $chain,
        ];
    }
}

function sec_status_factor(string $status): float
{
    $raw = strtolower(trim($status));
    if ($raw === 'pass') return 1.0;
    if ($raw === 'warn') return 0.55;
    return 0.0;
}

function sec_parse_hsts(string $value): array
{
    $parts = preg_split('/\s*;\s*/', strtolower($value)) ?: [];
    $maxAge = 0;
    $includeSub = false;
    $preload = false;
    foreach ($parts as $part) {
        $p = trim($part);
        if (str_starts_with($p, 'max-age=')) {
            $maxAge = (int) substr($p, 8);
        } elseif ($p === 'includesubdomains') {
            $includeSub = true;
        } elseif ($p === 'preload') {
            $preload = true;
        }
    }
    return ['max_age' => $maxAge, 'include_subdomains' => $includeSub, 'preload' => $preload];
}

function sec_find_mixed_content(string $body, string $finalUrl): array
{
    $finalScheme = strtolower((string) parse_url($finalUrl, PHP_URL_SCHEME));
    if ($finalScheme !== 'https') return [];
    $matches = [];
    if (preg_match_all('/\b(?:src|href)\s*=\s*["\']?(http:\/\/[^"\'\s>]+)/i', $body, $m)) {
        foreach ($m[1] as $u) $matches[] = $u;
    }
    if (preg_match_all('/url\(\s*["\']?(http:\/\/[^"\')\s]+)/i', $body, $m)) {
        foreach ($m[1] as $u) $matches[] = $u;
    }
    $matches = array_values(array_unique($matches));
    return array_slice($matches, 0, 50);
}

$fetch = sec_fetch_with_redirects($url, $timeout, $maxRedirects);
if (empty($fetch['ok'])) {
    respond_json(['error' => (string) ($fetch['error'] ?? 'Erreur audit securite')], 502);
}

$finalUrl = (string) ($fetch['final_url'] ?? $url);
$statusCode = (int) ($fetch['status_code'] ?? 0);
$responseMs = (int) ($fetch['response_time_ms'] ?? 0);
$contentType = strtolower((string) ($fetch['content_type'] ?? ''));
$headers = is_array($fetch['headers'] ?? null) ? $fetch['headers'] : [];
$setCookies = is_array($fetch['set_cookies'] ?? null) ? $fetch['set_cookies'] : [];
$body = (string) ($fetch['body'] ?? '');
$redirectCount = (int) ($fetch['redirect_count'] ?? 0);
$redirectChain = is_array($fetch['redirect_chain'] ?? null) ? $fetch['redirect_chain'] : [];

$finalScheme = strtolower((string) parse_url($finalUrl, PHP_URL_SCHEME));
$requestedScheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

$checks = [];
$recommendations = [];
$checklist = ['high' => [], 'medium' => [], 'low' => []];

function sec_add_check(array &$checks, string $key, string $status, int $weight, string $value = ''): void
{
    $checks[] = ['key' => $key, 'status' => $status, 'weight' => $weight, 'value' => $value];
}

// 1. HTTPS
sec_add_check($checks, 'https', $finalScheme === 'https' ? 'pass' : 'fail', 10, $finalScheme);

// 2. HTTP -> HTTPS redirect (only if user supplied http:// URL)
if ($requestedScheme === 'http') {
    $upgraded = false;
    foreach ($redirectChain as $hop) {
        if (!empty($hop['https'])) { $upgraded = true; break; }
    }
    sec_add_check($checks, 'http_to_https_redirect', $upgraded ? 'pass' : 'fail', 6, $upgraded ? 'upgraded' : 'no-redirect');
}

// 3-5. HSTS
$hstsHeader = (string) ($headers['strict-transport-security'] ?? '');
if ($hstsHeader === '') {
    sec_add_check($checks, 'hsts', 'fail', 8, 'absent');
    sec_add_check($checks, 'hsts_subdomains', 'fail', 2, 'absent');
    sec_add_check($checks, 'hsts_preload', 'warn', 2, 'absent');
} else {
    $hsts = sec_parse_hsts($hstsHeader);
    $maxAgeOk = $hsts['max_age'] >= 15552000; // 180d
    sec_add_check($checks, 'hsts', $maxAgeOk ? 'pass' : 'warn', 8, 'max-age=' . $hsts['max_age']);
    sec_add_check($checks, 'hsts_subdomains', $hsts['include_subdomains'] ? 'pass' : 'warn', 2, $hsts['include_subdomains'] ? 'yes' : 'no');
    sec_add_check($checks, 'hsts_preload', $hsts['preload'] ? 'pass' : 'warn', 2, $hsts['preload'] ? 'yes' : 'no');
}

// 6-8. CSP
$csp = (string) ($headers['content-security-policy'] ?? '');
$cspRO = (string) ($headers['content-security-policy-report-only'] ?? '');
if ($csp === '' && $cspRO === '') {
    sec_add_check($checks, 'csp', 'fail', 8, 'absent');
    sec_add_check($checks, 'csp_no_unsafe', 'fail', 5, 'no-csp');
} else {
    $cspEffective = $csp !== '' ? $csp : $cspRO;
    $cspStatus = $csp !== '' ? 'pass' : 'warn';
    sec_add_check($checks, 'csp', $cspStatus, 8, $csp !== '' ? 'enforcing' : 'report-only');
    $hasUnsafe = preg_match('/\bunsafe-inline\b|\bunsafe-eval\b/i', $cspEffective) === 1;
    sec_add_check($checks, 'csp_no_unsafe', $hasUnsafe ? 'warn' : 'pass', 5, $hasUnsafe ? 'unsafe-directive-present' : 'no-unsafe');
}

// 9. Frame protection (X-Frame-Options OR frame-ancestors in CSP)
$xfo = strtolower((string) ($headers['x-frame-options'] ?? ''));
$cspAll = $csp . ' ' . $cspRO;
$hasFA = preg_match('/frame-ancestors/i', $cspAll) === 1;
if ($xfo !== '' || $hasFA) {
    $xfoOk = $xfo === 'deny' || $xfo === 'sameorigin' || $hasFA;
    sec_add_check($checks, 'frame_protection', $xfoOk ? 'pass' : 'warn', 6, $hasFA ? 'csp-frame-ancestors' : $xfo);
} else {
    sec_add_check($checks, 'frame_protection', 'fail', 6, 'absent');
}

// 10. X-Content-Type-Options
$xcto = strtolower((string) ($headers['x-content-type-options'] ?? ''));
sec_add_check($checks, 'content_type_options', $xcto === 'nosniff' ? 'pass' : 'fail', 5, $xcto !== '' ? $xcto : 'absent');

// 11. Referrer-Policy
$rp = strtolower((string) ($headers['referrer-policy'] ?? ''));
$rpSafe = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin', 'no-referrer-when-downgrade'];
if ($rp === '') {
    sec_add_check($checks, 'referrer_policy', 'fail', 3, 'absent');
} else {
    sec_add_check($checks, 'referrer_policy', in_array($rp, $rpSafe, true) ? 'pass' : 'warn', 3, $rp);
}

// 12. Permissions-Policy
$pp = (string) ($headers['permissions-policy'] ?? '');
sec_add_check($checks, 'permissions_policy', $pp !== '' ? 'pass' : 'warn', 3, $pp !== '' ? 'present' : 'absent');

// 13. Server info leakage
$server = (string) ($headers['server'] ?? '');
$xpb = (string) ($headers['x-powered-by'] ?? '');
$leakVerbose = false;
if (preg_match('/\b\d+\.\d+/', $server)) $leakVerbose = true;
if ($xpb !== '') $leakVerbose = true;
sec_add_check($checks, 'server_info_leak', $leakVerbose ? 'warn' : 'pass', 2, trim($server . ' ' . ($xpb !== '' ? '(X-Powered-By: ' . $xpb . ')' : '')));

// 14. Mixed content
$mixed = sec_find_mixed_content($body, $finalUrl);
if ($finalScheme !== 'https') {
    sec_add_check($checks, 'mixed_content', 'warn', 9, 'not-https');
} else {
    $mixedCount = count($mixed);
    sec_add_check($checks, 'mixed_content', $mixedCount === 0 ? 'pass' : 'fail', 9, (string) $mixedCount);
}

// 15. X-XSS-Protection (deprecated)
$xxp = (string) ($headers['x-xss-protection'] ?? '');
if ($xxp === '' || str_starts_with(trim($xxp), '0')) {
    sec_add_check($checks, 'xss_protection_deprecated', 'pass', 1, $xxp === '' ? 'absent' : $xxp);
} else {
    sec_add_check($checks, 'xss_protection_deprecated', 'warn', 1, $xxp);
}

// 16. Cookies (only if Set-Cookie present)
if (count($setCookies) > 0) {
    $totalCookies = count($setCookies);
    $missingFlags = 0;
    foreach ($setCookies as $cookie) {
        $low = strtolower((string) $cookie);
        $secure = str_contains($low, '; secure');
        $httpOnly = str_contains($low, 'httponly');
        $sameSite = preg_match('/samesite=(strict|lax|none)/', $low) === 1;
        if (!$secure || !$httpOnly || !$sameSite) $missingFlags++;
    }
    $cookieStatus = $missingFlags === 0 ? 'pass' : ($missingFlags < $totalCookies ? 'warn' : 'fail');
    sec_add_check($checks, 'cookies_secure', $cookieStatus, 4, $totalCookies . ' cookie(s), ' . $missingFlags . ' incomplete');
}

// Compute score
$totalWeight = 0;
$earnedWeight = 0.0;
foreach ($checks as $c) {
    $totalWeight += (int) $c['weight'];
    $earnedWeight += (float) $c['weight'] * sec_status_factor((string) $c['status']);
}
$score = $totalWeight > 0 ? (int) round($earnedWeight / $totalWeight * 100) : 0;

// Recommendations + checklist
$RECOS = [
    'https' => ['high', 'security_reco_https'],
    'http_to_https_redirect' => ['high', 'security_reco_http_redirect'],
    'hsts' => ['high', 'security_reco_hsts'],
    'hsts_subdomains' => ['low', 'security_reco_hsts_subdomains'],
    'hsts_preload' => ['low', 'security_reco_hsts_preload'],
    'csp' => ['high', 'security_reco_csp'],
    'csp_no_unsafe' => ['medium', 'security_reco_csp_unsafe'],
    'frame_protection' => ['medium', 'security_reco_frame_protection'],
    'content_type_options' => ['medium', 'security_reco_content_type_options'],
    'referrer_policy' => ['medium', 'security_reco_referrer_policy'],
    'permissions_policy' => ['low', 'security_reco_permissions_policy'],
    'server_info_leak' => ['low', 'security_reco_server_leak'],
    'mixed_content' => ['high', 'security_reco_mixed_content'],
    'xss_protection_deprecated' => ['low', 'security_reco_xss_deprecated'],
    'cookies_secure' => ['medium', 'security_reco_cookies'],
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
    'checks_pass' => count(array_filter($checks, fn($c) => $c['status'] === 'pass')),
    'checks_warn' => count(array_filter($checks, fn($c) => $c['status'] === 'warn')),
    'checks_fail' => count(array_filter($checks, fn($c) => $c['status'] === 'fail')),
    'mixed_content_count' => count($mixed),
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
        'redirect_chain' => $redirectChain,
        'score' => $score,
        'kpis' => $kpis,
        'checks' => $checks,
        'recommendations' => $recommendations,
        'checklist' => $checklist,
        'metrics' => [
            'cookies_count' => count($setCookies),
            'mixed_content_urls' => $mixed,
            'server' => $server,
            'x_powered_by' => $xpb,
        ],
    ],
], 200);
