<?php
declare(strict_types=1);

const STORAGE_DIR = __DIR__ . '/storage';
const JOBS_DIR = STORAGE_DIR . '/jobs';
const MESH_JOBS_DIR = STORAGE_DIR . '/mesh_jobs';
const REPORTS_DIR = STORAGE_DIR . '/reports';
const LOGS_DIR = STORAGE_DIR . '/logs';
const RATE_LIMIT_DIR = STORAGE_DIR . '/rate_limit';

if (PHP_SAPI !== 'cli') {
    @ini_set('display_errors', '0');
    @ini_set('html_errors', '0');
    if (ob_get_level() === 0) {
        ob_start();
    }
}

function respond_json(array $payload, int $status = 200): void
{
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function ensure_storage_dirs(): void
{
    foreach ([STORAGE_DIR, JOBS_DIR, MESH_JOBS_DIR, REPORTS_DIR, LOGS_DIR, RATE_LIMIT_DIR] as $dir) {
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }
    }
}

function get_json_input(): array
{
    $raw = file_get_contents('php://input');
    if (!is_string($raw) || trim($raw) === '') {
        return [];
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function read_csv_line($handle)
{
    // Keep explicit escape char to avoid PHP 8.4+ deprecation warnings.
    return fgetcsv($handle, 0, ',', '"', '\\');
}

function clamp_int(mixed $value, int $min, int $max, int $default): int
{
    if (!is_numeric((string) $value)) {
        return $default;
    }

    $number = (int) $value;
    if ($number < $min) {
        return $min;
    }
    if ($number > $max) {
        return $max;
    }
    return $number;
}

function clamp_float(mixed $value, float $min, float $max, float $default): float
{
    if (!is_numeric((string) $value)) {
        return $default;
    }

    $number = (float) $value;
    if ($number < $min) {
        return $min;
    }
    if ($number > $max) {
        return $max;
    }
    return $number;
}

function sanitize_job_id(string $jobId): ?string
{
    $jobId = strtolower(trim($jobId));
    if (!preg_match('/^[a-f0-9]{20}$/', $jobId)) {
        return null;
    }
    return $jobId;
}

function normalize_ip(string $ip): string
{
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    }
    return '0.0.0.0';
}

function client_ip(): string
{
    $candidate = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    return normalize_ip($candidate);
}

function expose_debug_details(): bool
{
    $raw = strtolower(trim((string) getenv('SEO_TOOL_EXPOSE_DEBUG')));
    return in_array($raw, ['1', 'true', 'yes', 'on'], true);
}

function job_path(string $jobId): string
{
    return JOBS_DIR . '/' . $jobId . '.json';
}

function report_path(string $jobId): string
{
    return REPORTS_DIR . '/' . $jobId . '.csv';
}

function conflicts_report_path(string $jobId): string
{
    return REPORTS_DIR . '/' . $jobId . '_sitemap_indexation_conflicts.csv';
}

function mesh_result_path(string $meshId): string
{
    return REPORTS_DIR . '/' . $meshId . '_mesh.json';
}

function log_path(string $jobId): string
{
    return LOGS_DIR . '/' . $jobId . '.log';
}

function mesh_job_path(string $jobId): string
{
    return MESH_JOBS_DIR . '/' . $jobId . '.json';
}

function mesh_output_path(string $jobId): string
{
    return REPORTS_DIR . '/' . $jobId . '_mesh_payload.json';
}

function mesh_progress_path(string $jobId): string
{
    return REPORTS_DIR . '/' . $jobId . '_mesh_progress.json';
}

function mesh_log_path(string $jobId): string
{
    return LOGS_DIR . '/' . $jobId . '_mesh.log';
}

function read_job(string $jobId): ?array
{
    $path = job_path($jobId);
    if (!is_file($path)) {
        return null;
    }

    $raw = file_get_contents($path);
    if (!is_string($raw) || trim($raw) === '') {
        return null;
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : null;
}

function write_job(string $jobId, array $data): bool
{
    $path = job_path($jobId);
    return file_put_contents(
        $path,
        json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    ) !== false;
}

function read_mesh_job(string $jobId): ?array
{
    $path = mesh_job_path($jobId);
    if (!is_file($path)) {
        return null;
    }

    $raw = file_get_contents($path);
    if (!is_string($raw) || trim($raw) === '') {
        return null;
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : null;
}

function write_mesh_job(string $jobId, array $data): bool
{
    $path = mesh_job_path($jobId);
    return file_put_contents(
        $path,
        json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    ) !== false;
}

function is_public_ip(string $ip): bool
{
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) !== false;
}

function validate_public_url(string $url, string &$error): bool
{
    $error = '';
    $url = trim($url);

    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        $error = 'URL invalide.';
        return false;
    }

    $parts = parse_url($url);
    if (!is_array($parts)) {
        $error = 'URL invalide.';
        return false;
    }

    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    if (!in_array($scheme, ['http', 'https'], true)) {
        $error = 'Le sitemap doit etre en HTTP/HTTPS.';
        return false;
    }

    if (!empty($parts['user']) || !empty($parts['pass'])) {
        $error = 'Credentials dans URL interdites.';
        return false;
    }

    $host = strtolower((string) ($parts['host'] ?? ''));
    if ($host === '') {
        $error = 'Host manquant dans l URL.';
        return false;
    }

    $port = isset($parts['port']) ? (int) $parts['port'] : null;
    if ($port !== null && !in_array($port, [80, 443], true)) {
        $error = 'Port non autorise (seulement 80/443).';
        return false;
    }

    $blockedHosts = ['localhost', '127.0.0.1', '::1'];
    $blockedSuffixes = ['.local', '.localhost', '.internal', '.test', '.home.arpa'];

    if (in_array($host, $blockedHosts, true)) {
        $error = 'Host local interdit.';
        return false;
    }
    foreach ($blockedSuffixes as $suffix) {
        if (str_ends_with($host, $suffix)) {
            $error = 'Host prive/interne interdit.';
            return false;
        }
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        if (!is_public_ip($host)) {
            $error = 'IP privee/reservee interdite.';
            return false;
        }
        return true;
    }

    $recordsA = dns_get_record($host, DNS_A);
    $recordsAAAA = dns_get_record($host, DNS_AAAA);

    $ips = [];
    if (is_array($recordsA)) {
        foreach ($recordsA as $record) {
            if (!empty($record['ip'])) {
                $ips[] = (string) $record['ip'];
            }
        }
    }
    if (is_array($recordsAAAA)) {
        foreach ($recordsAAAA as $record) {
            if (!empty($record['ipv6'])) {
                $ips[] = (string) $record['ipv6'];
            }
        }
    }

    if (count($ips) === 0) {
        $error = 'Impossible de resoudre le domaine.';
        return false;
    }

    foreach ($ips as $ip) {
        if (!is_public_ip($ip)) {
            $error = 'Le domaine resolve vers une IP privee/reservee.';
            return false;
        }
    }

    return true;
}

function resolve_public_ip_for_host(string $host, string &$error): ?string
{
    $error = '';
    $host = strtolower(trim($host));
    if ($host === '') {
        $error = 'Host manquant.';
        return null;
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        if (!is_public_ip($host)) {
            $error = 'IP privee/reservee interdite.';
            return null;
        }
        return $host;
    }

    $recordsA = dns_get_record($host, DNS_A);
    $recordsAAAA = dns_get_record($host, DNS_AAAA);
    $ips = [];

    if (is_array($recordsA)) {
        foreach ($recordsA as $record) {
            if (!empty($record['ip'])) {
                $ips[] = (string) $record['ip'];
            }
        }
    }
    if (is_array($recordsAAAA)) {
        foreach ($recordsAAAA as $record) {
            if (!empty($record['ipv6'])) {
                $ips[] = (string) $record['ipv6'];
            }
        }
    }

    if (!$ips) {
        $error = 'Impossible de resoudre le domaine.';
        return null;
    }

    sort($ips, SORT_STRING);
    foreach ($ips as $ip) {
        if (is_public_ip($ip)) {
            return $ip;
        }
    }

    $error = 'Le domaine ne resolve pas vers une IP publique.';
    return null;
}

function rate_limit_path(string $bucket, string $identifier): string
{
    $bucketSafe = preg_replace('/[^a-z0-9_-]/i', '_', strtolower($bucket)) ?: 'default';
    $hash = hash('sha256', $identifier);
    return RATE_LIMIT_DIR . '/' . $bucketSafe . '_' . $hash . '.json';
}

function enforce_rate_limit(string $bucket, string $identifier, int $maxRequests, int $windowSeconds): array
{
    ensure_storage_dirs();

    $path = rate_limit_path($bucket, $identifier);
    $now = time();

    $timestamps = [];
    if (is_file($path)) {
        $raw = file_get_contents($path);
        $decoded = json_decode((string) $raw, true);
        if (is_array($decoded)) {
            foreach ($decoded as $ts) {
                $value = (int) $ts;
                if ($value > 0) {
                    $timestamps[] = $value;
                }
            }
        }
    }

    $minAllowed = $now - $windowSeconds;
    $timestamps = array_values(array_filter($timestamps, static fn(int $ts): bool => $ts > $minAllowed));

    if (count($timestamps) >= $maxRequests) {
        sort($timestamps);
        $oldest = $timestamps[0];
        $retryAfter = max(1, ($oldest + $windowSeconds) - $now);
        file_put_contents($path, json_encode($timestamps), LOCK_EX);

        return [
            'allowed' => false,
            'retry_after' => $retryAfter,
            'remaining' => 0,
            'limit' => $maxRequests,
            'window_seconds' => $windowSeconds,
        ];
    }

    $timestamps[] = $now;
    file_put_contents($path, json_encode($timestamps), LOCK_EX);

    return [
        'allowed' => true,
        'retry_after' => 0,
        'remaining' => max(0, $maxRequests - count($timestamps)),
        'limit' => $maxRequests,
        'window_seconds' => $windowSeconds,
    ];
}

function count_active_jobs(?string $ip = null): int
{
    $count = 0;
    $files = glob(JOBS_DIR . '/*.json') ?: [];

    foreach ($files as $file) {
        $raw = file_get_contents($file);
        if (!is_string($raw) || $raw === '') {
            continue;
        }

        $job = json_decode($raw, true);
        if (!is_array($job)) {
            continue;
        }

        $status = (string) ($job['status'] ?? '');
        if (!in_array($status, ['queued', 'running'], true)) {
            continue;
        }

        if ($ip !== null) {
            $jobIp = normalize_ip((string) ($job['client_ip'] ?? ''));
            if ($jobIp !== $ip) {
                continue;
            }
        }

        $count++;
    }

    return $count;
}

function count_active_mesh_jobs(?string $ip = null): int
{
    $count = 0;
    $files = glob(MESH_JOBS_DIR . '/*.json') ?: [];

    foreach ($files as $file) {
        $raw = file_get_contents($file);
        if (!is_string($raw) || $raw === '') {
            continue;
        }

        $job = json_decode($raw, true);
        if (!is_array($job)) {
            continue;
        }

        $status = (string) ($job['status'] ?? '');
        if (!in_array($status, ['queued', 'running'], true)) {
            continue;
        }

        if ($ip !== null) {
            $jobIp = normalize_ip((string) ($job['client_ip'] ?? ''));
            if ($jobIp !== $ip) {
                continue;
            }
        }

        $count++;
    }

    return $count;
}

function is_process_running(int $pid): bool
{
    if ($pid <= 0) {
        return false;
    }

    if (function_exists('posix_kill')) {
        return @posix_kill($pid, 0);
    }

    if (!function_exists('shell_exec')) {
        return false;
    }

    $output = shell_exec('ps -p ' . (int) $pid . ' -o pid=');
    return is_string($output) && trim($output) !== '';
}

function tail_file_lines(string $path, int $maxLines = 40): array
{
    if (!is_file($path)) {
        return [];
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if (!is_array($lines)) {
        return [];
    }

    $tail = array_slice($lines, -$maxLines);
    return array_values(array_map(static fn($line) => (string) $line, $tail));
}

function build_csv_summary(string $path): array
{
    $summary = [
        'total' => 0,
        'with_issues' => 0,
        'without_issues' => 0,
    ];

    if (!is_file($path)) {
        return $summary;
    }

    $handle = fopen($path, 'rb');
    if ($handle === false) {
        return $summary;
    }

    $headers = read_csv_line($handle);
    if (!is_array($headers)) {
        fclose($handle);
        return $summary;
    }

    $issuesIndex = array_search('issues', $headers, true);

    while (($row = read_csv_line($handle)) !== false) {
        $summary['total']++;
        $issues = '';
        if ($issuesIndex !== false && isset($row[$issuesIndex])) {
            $issues = trim((string) $row[$issuesIndex]);
        }

        if ($issues === '') {
            $summary['without_issues']++;
        } else {
            $summary['with_issues']++;
        }
    }

    fclose($handle);
    return $summary;
}

function build_csv_insights(string $path): array
{
    $insights = [
        'priority_counts' => [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'none' => 0,
        ],
        'top_issues' => [],
        'conflicts_count' => 0,
        'top_conflict_reasons' => [],
        'domain_overview' => [
            'totals' => [
                'urls' => 0,
                'indexable' => 0,
                'non_200' => 0,
                'redirects' => 0,
                'robots_blocked' => 0,
                'noindex' => 0,
                'conflicts' => 0,
                'canonical_cross_domain' => 0,
                'hreflang_missing_x_default' => 0,
            ],
            'rates' => [
                'indexable_pct' => 0.0,
                'non_200_pct' => 0.0,
                'conflicts_pct' => 0.0,
            ],
            'top_sections' => [],
            'actions' => [],
        ],
    ];

    if (!is_file($path)) {
        return $insights;
    }

    $handle = fopen($path, 'rb');
    if ($handle === false) {
        return $insights;
    }

    $headers = read_csv_line($handle);
    if (!is_array($headers)) {
        fclose($handle);
        return $insights;
    }

    $issuesIdx = array_search('issues', $headers, true);
    $priorityIdx = array_search('priority_level', $headers, true);
    $priorityScoreIdx = array_search('priority_score', $headers, true);
    $conflictIdx = array_search('sitemap_indexation_conflict', $headers, true);
    $conflictReasonsIdx = array_search('sitemap_indexation_conflict_reasons', $headers, true);
    $statusIdx = array_search('status', $headers, true);
    $indexableIdx = array_search('is_indexable', $headers, true);
    $robotsBlockedIdx = array_search('robots_txt_blocked', $headers, true);
    $robotsMetaIdx = array_search('robots_meta', $headers, true);
    $xRobotsIdx = array_search('x_robots_tag', $headers, true);
    $canonicalCrossDomainIdx = array_search('canonical_cross_domain', $headers, true);
    $hreflangCountIdx = array_search('hreflang_count', $headers, true);
    $hreflangHasXDefaultIdx = array_search('hreflang_has_x_default', $headers, true);
    $finalUrlIdx = array_search('final_url', $headers, true);
    $urlIdx = array_search('url', $headers, true);

    $issueCounts = [];
    $conflictReasonCounts = [];
    $sectionStats = [];
    $totals = $insights['domain_overview']['totals'];

    $toBool = static function ($value): bool {
        $raw = strtolower(trim((string) $value));
        return in_array($raw, ['1', 'true', 'yes'], true);
    };
    $toInt = static function ($value): int {
        return (int) (is_numeric($value) ? $value : 0);
    };
    $sectionKeyFromUrl = static function (string $url): string {
        $path = (string) parse_url($url, PHP_URL_PATH);
        $parts = array_values(array_filter(explode('/', strtolower($path)), static fn($p) => $p !== ''));
        if (count($parts) === 0) {
            return '/';
        }
        $localeSet = ['en', 'fr', 'de', 'es', 'it', 'pt', 'nl'];
        if (in_array($parts[0], $localeSet, true) && isset($parts[1])) {
            return $parts[0] . '/' . $parts[1];
        }
        return $parts[0];
    };

    while (($row = read_csv_line($handle)) !== false) {
        $issues = '';
        $totals['urls']++;

        $status = $toInt($statusIdx !== false ? ($row[$statusIdx] ?? 0) : 0);
        if ($status !== 200) {
            $totals['non_200']++;
        }
        if ($status >= 300 && $status < 400) {
            $totals['redirects']++;
        }

        $isIndexable = $toBool($indexableIdx !== false ? ($row[$indexableIdx] ?? '') : '');
        if ($isIndexable) {
            $totals['indexable']++;
        }

        $robotsBlocked = $toBool($robotsBlockedIdx !== false ? ($row[$robotsBlockedIdx] ?? '') : '');
        if ($robotsBlocked) {
            $totals['robots_blocked']++;
        }

        $robotsMeta = strtolower(trim((string) ($robotsMetaIdx !== false ? ($row[$robotsMetaIdx] ?? '') : '')));
        $xRobots = strtolower(trim((string) ($xRobotsIdx !== false ? ($row[$xRobotsIdx] ?? '') : '')));
        if (str_contains($robotsMeta, 'noindex') || str_contains($xRobots, 'noindex')) {
            $totals['noindex']++;
        }

        $canonicalCrossDomain = $toBool($canonicalCrossDomainIdx !== false ? ($row[$canonicalCrossDomainIdx] ?? '') : '');
        if ($canonicalCrossDomain) {
            $totals['canonical_cross_domain']++;
        }

        $hreflangCount = $toInt($hreflangCountIdx !== false ? ($row[$hreflangCountIdx] ?? 0) : 0);
        $hreflangHasXDefault = $toBool($hreflangHasXDefaultIdx !== false ? ($row[$hreflangHasXDefaultIdx] ?? '') : '');
        if ($hreflangCount >= 2 && !$hreflangHasXDefault) {
            $totals['hreflang_missing_x_default']++;
        }

        if ($priorityIdx !== false) {
            $priority = strtolower(trim((string) ($row[$priorityIdx] ?? 'none')));
            if (!isset($insights['priority_counts'][$priority])) {
                $priority = 'none';
            }
            $insights['priority_counts'][$priority]++;
        }

        if ($issuesIdx !== false) {
            $issues = trim((string) ($row[$issuesIdx] ?? ''));
            if ($issues !== '') {
                foreach (explode(' | ', $issues) as $issue) {
                    $token = trim($issue);
                    if ($token === '') {
                        continue;
                    }
                    $issueCounts[$token] = ($issueCounts[$token] ?? 0) + 1;
                }
            }
        }

        $hasConflict = false;
        if ($conflictIdx !== false) {
            $value = strtolower(trim((string) ($row[$conflictIdx] ?? '')));
            $hasConflict = in_array($value, ['1', 'true', 'yes'], true);
        }
        if ($hasConflict) {
            $insights['conflicts_count']++;
            $totals['conflicts']++;
            if ($conflictReasonsIdx !== false) {
                $reasons = trim((string) ($row[$conflictReasonsIdx] ?? ''));
                if ($reasons !== '') {
                    foreach (explode(' | ', $reasons) as $reason) {
                        $token = trim($reason);
                        if ($token === '') {
                            continue;
                        }
                        $conflictReasonCounts[$token] = ($conflictReasonCounts[$token] ?? 0) + 1;
                    }
                }
            }
        }

        $effectiveUrl = trim((string) (
            ($finalUrlIdx !== false ? ($row[$finalUrlIdx] ?? '') : '')
            ?: ($urlIdx !== false ? ($row[$urlIdx] ?? '') : '')
        ));
        $sectionKey = $sectionKeyFromUrl($effectiveUrl);
        if (!isset($sectionStats[$sectionKey])) {
            $sectionStats[$sectionKey] = [
                'section' => $sectionKey,
                'urls' => 0,
                'with_issues' => 0,
                'priority_score_sum' => 0,
                'issue_counts' => [],
            ];
        }
        $sectionStats[$sectionKey]['urls']++;
        if (isset($issues) && $issues !== '') {
            $sectionStats[$sectionKey]['with_issues']++;
            foreach (explode(' | ', $issues) as $issue) {
                $token = trim($issue);
                if ($token === '') {
                    continue;
                }
                $sectionStats[$sectionKey]['issue_counts'][$token] = ($sectionStats[$sectionKey]['issue_counts'][$token] ?? 0) + 1;
            }
        }
        $sectionStats[$sectionKey]['priority_score_sum'] += $toInt($priorityScoreIdx !== false ? ($row[$priorityScoreIdx] ?? 0) : 0);
    }
    fclose($handle);

    arsort($issueCounts);
    arsort($conflictReasonCounts);

    $topIssues = array_slice($issueCounts, 0, 8, true);
    foreach ($topIssues as $issue => $count) {
        $insights['top_issues'][] = ['issue' => $issue, 'count' => $count];
    }

    $topConflictReasons = array_slice($conflictReasonCounts, 0, 6, true);
    foreach ($topConflictReasons as $reason => $count) {
        $insights['top_conflict_reasons'][] = ['reason' => $reason, 'count' => $count];
    }

    $totalUrls = max(1, (int) $totals['urls']);
    $insights['domain_overview']['totals'] = $totals;
    $insights['domain_overview']['rates'] = [
        'indexable_pct' => round(((int) $totals['indexable'] / $totalUrls) * 100, 1),
        'non_200_pct' => round(((int) $totals['non_200'] / $totalUrls) * 100, 1),
        'conflicts_pct' => round(((int) $totals['conflicts'] / $totalUrls) * 100, 1),
    ];

    $sections = [];
    foreach ($sectionStats as $section) {
        $urls = max(1, (int) ($section['urls'] ?? 0));
        $withIssues = (int) ($section['with_issues'] ?? 0);
        $issueRate = round(($withIssues / $urls) * 100, 1);
        $avgPriorityScore = round(((int) ($section['priority_score_sum'] ?? 0)) / $urls, 1);
        $sectionIssueCounts = $section['issue_counts'] ?? [];
        arsort($sectionIssueCounts);
        $topIssue = '';
        if (count($sectionIssueCounts) > 0) {
            $topIssue = (string) array_key_first($sectionIssueCounts);
        }
        $sections[] = [
            'section' => (string) ($section['section'] ?? '/'),
            'urls' => (int) ($section['urls'] ?? 0),
            'with_issues' => $withIssues,
            'issue_rate' => $issueRate,
            'avg_priority_score' => $avgPriorityScore,
            'top_issue' => $topIssue,
        ];
    }

    usort(
        $sections,
        static function (array $a, array $b): int {
            $aRate = (float) ($a['issue_rate'] ?? 0);
            $bRate = (float) ($b['issue_rate'] ?? 0);
            if ($aRate !== $bRate) {
                return $aRate < $bRate ? 1 : -1;
            }
            $aIssues = (int) ($a['with_issues'] ?? 0);
            $bIssues = (int) ($b['with_issues'] ?? 0);
            if ($aIssues !== $bIssues) {
                return $aIssues < $bIssues ? 1 : -1;
            }
            $aUrls = (int) ($a['urls'] ?? 0);
            $bUrls = (int) ($b['urls'] ?? 0);
            return $aUrls < $bUrls ? 1 : -1;
        }
    );
    $insights['domain_overview']['top_sections'] = array_slice($sections, 0, 8);

    $actions = [];
    $actionCandidates = [
        ['action_key' => 'fix_sitemap_indexation_conflicts', 'count' => (int) $totals['conflicts']],
        ['action_key' => 'fix_non_200_in_sitemap', 'count' => (int) $totals['non_200']],
        ['action_key' => 'fix_robots_blocked_in_sitemap', 'count' => (int) $totals['robots_blocked']],
        ['action_key' => 'fix_noindex_in_sitemap', 'count' => (int) $totals['noindex']],
        ['action_key' => 'fix_cross_domain_canonicals', 'count' => (int) $totals['canonical_cross_domain']],
        ['action_key' => 'add_x_default_hreflang', 'count' => (int) $totals['hreflang_missing_x_default']],
    ];
    foreach ($actionCandidates as $candidate) {
        if (($candidate['count'] ?? 0) <= 0) {
            continue;
        }
        $actions[] = $candidate;
    }
    usort(
        $actions,
        static function (array $a, array $b): int {
            return ((int) ($b['count'] ?? 0)) <=> ((int) ($a['count'] ?? 0));
        }
    );
    $insights['domain_overview']['actions'] = array_slice($actions, 0, 6);

    return $insights;
}

function read_csv_preview(string $path, int $maxRows = 100): array
{
    $result = [
        'headers' => [],
        'rows' => [],
        'total_rows' => 0,
        'truncated' => false,
    ];

    if (!is_file($path)) {
        return $result;
    }

    $handle = fopen($path, 'rb');
    if ($handle === false) {
        return $result;
    }

    $headers = read_csv_line($handle);
    if (!is_array($headers)) {
        fclose($handle);
        return $result;
    }

    $result['headers'] = array_values(array_map(static fn($h) => (string) $h, $headers));

    $rowIndex = 0;
    while (($row = read_csv_line($handle)) !== false) {
        $rowIndex++;

        if ($rowIndex <= $maxRows) {
            $assoc = [];
            foreach ($result['headers'] as $i => $header) {
                $value = (string) ($row[$i] ?? '');
                if (strlen($value) > 4000) {
                    $value = substr($value, 0, 4000) . '...';
                }
                $assoc[$header] = $value;
            }
            $result['rows'][] = $assoc;
        }
    }

    fclose($handle);

    $result['total_rows'] = $rowIndex;
    $result['truncated'] = $rowIndex > $maxRows;
    return $result;
}

function csv_issue_tokens(string $issues): array
{
    $parts = explode(' | ', trim($issues));
    $tokens = [];
    foreach ($parts as $part) {
        $value = trim($part);
        if ($value === '') {
            continue;
        }
        $tokens[$value] = true;
    }
    return array_keys($tokens);
}

function read_csv_issue_map(string $path): array
{
    $map = [];
    if (!is_file($path)) {
        return $map;
    }

    $handle = fopen($path, 'rb');
    if ($handle === false) {
        return $map;
    }

    $headers = read_csv_line($handle);
    if (!is_array($headers)) {
        fclose($handle);
        return $map;
    }

    $urlIdx = array_search('url', $headers, true);
    $issuesIdx = array_search('issues', $headers, true);
    $priorityLevelIdx = array_search('priority_level', $headers, true);
    $priorityScoreIdx = array_search('priority_score', $headers, true);

    if ($urlIdx === false || $issuesIdx === false) {
        fclose($handle);
        return $map;
    }

    while (($row = read_csv_line($handle)) !== false) {
        $url = trim((string) ($row[$urlIdx] ?? ''));
        if ($url === '') {
            continue;
        }
        $issues = trim((string) ($row[$issuesIdx] ?? ''));
        $priorityLevel = strtolower(trim((string) ($row[$priorityLevelIdx] ?? 'none')));
        if (!in_array($priorityLevel, ['critical', 'high', 'medium', 'low', 'none'], true)) {
            $priorityLevel = 'none';
        }
        $priorityScore = (int) ($row[$priorityScoreIdx] ?? 0);

        $map[$url] = [
            'issues' => $issues,
            'issue_tokens' => csv_issue_tokens($issues),
            'has_issues' => $issues !== '',
            'priority_level' => $priorityLevel,
            'priority_score' => $priorityScore,
        ];
    }

    fclose($handle);
    return $map;
}

function build_scan_diff(string $currentPath, string $previousPath): array
{
    $current = read_csv_issue_map($currentPath);
    $previous = read_csv_issue_map($previousPath);

    $currentUrls = array_keys($current);
    $previousUrls = array_keys($previous);

    $currentSet = array_fill_keys($currentUrls, true);
    $previousSet = array_fill_keys($previousUrls, true);

    $allUrls = array_values(array_unique(array_merge($currentUrls, $previousUrls)));

    $newIssueUrls = 0;
    $resolvedIssueUrls = 0;
    $changedIssueUrls = 0;
    $addedUrls = 0;
    $removedUrls = 0;

    $newIssueTypes = [];
    $resolvedIssueTypes = [];

    foreach ($allUrls as $url) {
        $inCurrent = isset($currentSet[$url]);
        $inPrevious = isset($previousSet[$url]);

        if ($inCurrent && !$inPrevious) {
            $addedUrls++;
        } elseif (!$inCurrent && $inPrevious) {
            $removedUrls++;
        }

        $currentRow = $current[$url] ?? null;
        $previousRow = $previous[$url] ?? null;

        $currentHasIssues = (bool) ($currentRow['has_issues'] ?? false);
        $previousHasIssues = (bool) ($previousRow['has_issues'] ?? false);

        if (!$previousHasIssues && $currentHasIssues) {
            $newIssueUrls++;
        } elseif ($previousHasIssues && !$currentHasIssues) {
            $resolvedIssueUrls++;
        } elseif ($previousHasIssues && $currentHasIssues) {
            $prevIssues = (string) ($previousRow['issues'] ?? '');
            $currIssues = (string) ($currentRow['issues'] ?? '');
            if ($prevIssues !== $currIssues) {
                $changedIssueUrls++;
            }
        }

        $prevTokens = array_fill_keys($previousRow['issue_tokens'] ?? [], true);
        $currTokens = array_fill_keys($currentRow['issue_tokens'] ?? [], true);

        foreach ($currTokens as $token => $_) {
            if (!isset($prevTokens[$token])) {
                $newIssueTypes[$token] = ($newIssueTypes[$token] ?? 0) + 1;
            }
        }
        foreach ($prevTokens as $token => $_) {
            if (!isset($currTokens[$token])) {
                $resolvedIssueTypes[$token] = ($resolvedIssueTypes[$token] ?? 0) + 1;
            }
        }
    }

    $severityOrder = ['critical', 'high', 'medium', 'low', 'none'];
    $severityCurrent = array_fill_keys($severityOrder, 0);
    $severityPrevious = array_fill_keys($severityOrder, 0);

    foreach ($current as $row) {
        $level = $row['priority_level'] ?? 'none';
        if (!isset($severityCurrent[$level])) {
            $severityCurrent[$level] = 0;
        }
        $severityCurrent[$level]++;
    }
    foreach ($previous as $row) {
        $level = $row['priority_level'] ?? 'none';
        if (!isset($severityPrevious[$level])) {
            $severityPrevious[$level] = 0;
        }
        $severityPrevious[$level]++;
    }

    arsort($newIssueTypes);
    arsort($resolvedIssueTypes);

    return [
        'current_urls' => count($currentUrls),
        'previous_urls' => count($previousUrls),
        'added_urls' => $addedUrls,
        'removed_urls' => $removedUrls,
        'new_issue_urls' => $newIssueUrls,
        'resolved_issue_urls' => $resolvedIssueUrls,
        'changed_issue_urls' => $changedIssueUrls,
        'severity_current' => $severityCurrent,
        'severity_previous' => $severityPrevious,
        'top_new_issue_types' => array_slice($newIssueTypes, 0, 8, true),
        'top_resolved_issue_types' => array_slice($resolvedIssueTypes, 0, 8, true),
    ];
}

function find_previous_completed_job_for_sitemap(string $sitemap, string $excludeJobId): ?array
{
    $files = glob(JOBS_DIR . '/*.json') ?: [];
    $candidates = [];

    foreach ($files as $file) {
        $raw = file_get_contents($file);
        if (!is_string($raw) || $raw === '') {
            continue;
        }
        $job = json_decode($raw, true);
        if (!is_array($job)) {
            continue;
        }
        if (($job['job_id'] ?? '') === $excludeJobId) {
            continue;
        }
        if (($job['status'] ?? '') !== 'completed') {
            continue;
        }
        if (($job['sitemap'] ?? '') !== $sitemap) {
            continue;
        }

        $jobId = (string) ($job['job_id'] ?? '');
        if ($jobId === '' || !is_file(report_path($jobId))) {
            continue;
        }
        $candidates[] = $job;
    }

    if (count($candidates) === 0) {
        return null;
    }

    usort(
        $candidates,
        static function (array $a, array $b): int {
            $aTime = (string) ($a['completed_at'] ?? $a['created_at'] ?? '');
            $bTime = (string) ($b['completed_at'] ?? $b['created_at'] ?? '');
            return strcmp($bTime, $aTime);
        }
    );

    return $candidates[0] ?? null;
}

function list_recent_completed_jobs_for_sitemap(string $sitemap, int $limit = 8): array
{
    $files = glob(JOBS_DIR . '/*.json') ?: [];
    $runs = [];

    foreach ($files as $file) {
        $raw = file_get_contents($file);
        if (!is_string($raw) || $raw === '') {
            continue;
        }
        $job = json_decode($raw, true);
        if (!is_array($job)) {
            continue;
        }
        if (($job['status'] ?? '') !== 'completed') {
            continue;
        }
        if (($job['sitemap'] ?? '') !== $sitemap) {
            continue;
        }

        $jobId = (string) ($job['job_id'] ?? '');
        if ($jobId === '') {
            continue;
        }

        $summary = $job['summary_cache'] ?? null;
        if (!is_array($summary) && is_file(report_path($jobId))) {
            $summary = build_csv_summary(report_path($jobId));
        }

        $runs[] = [
            'job_id' => $jobId,
            'created_at' => $job['created_at'] ?? null,
            'completed_at' => $job['completed_at'] ?? null,
            'summary' => is_array($summary) ? $summary : ['total' => 0, 'with_issues' => 0, 'without_issues' => 0],
        ];
    }

    usort(
        $runs,
        static function (array $a, array $b): int {
            $aTime = (string) ($a['completed_at'] ?? $a['created_at'] ?? '');
            $bTime = (string) ($b['completed_at'] ?? $b['created_at'] ?? '');
            return strcmp($bTime, $aTime);
        }
    );

    return array_slice($runs, 0, max(1, $limit));
}

function seo_script_path(): string
{
    return __DIR__ . '/seo_sitemap_checker.py';
}

function internal_mesh_script_path(): string
{
    return __DIR__ . '/internal_link_mesh.py';
}

function write_mesh_result(string $meshId, array $payload): bool
{
    return file_put_contents(
        mesh_result_path($meshId),
        json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        LOCK_EX
    ) !== false;
}

function read_mesh_result(string $meshId): ?array
{
    $path = mesh_result_path($meshId);
    if (!is_file($path)) {
        return null;
    }

    $raw = file_get_contents($path);
    if (!is_string($raw) || trim($raw) === '') {
        return null;
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : null;
}
