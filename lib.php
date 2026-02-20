<?php
declare(strict_types=1);

const STORAGE_DIR = __DIR__ . '/storage';
const JOBS_DIR = STORAGE_DIR . '/jobs';
const REPORTS_DIR = STORAGE_DIR . '/reports';
const LOGS_DIR = STORAGE_DIR . '/logs';
const RATE_LIMIT_DIR = STORAGE_DIR . '/rate_limit';

function respond_json(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function ensure_storage_dirs(): void
{
    foreach ([STORAGE_DIR, JOBS_DIR, REPORTS_DIR, LOGS_DIR, RATE_LIMIT_DIR] as $dir) {
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

function log_path(string $jobId): string
{
    return LOGS_DIR . '/' . $jobId . '.log';
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

    $headers = fgetcsv($handle);
    if (!is_array($headers)) {
        fclose($handle);
        return $summary;
    }

    $issuesIndex = array_search('issues', $headers, true);

    while (($row = fgetcsv($handle)) !== false) {
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
    ];

    if (!is_file($path)) {
        return $insights;
    }

    $handle = fopen($path, 'rb');
    if ($handle === false) {
        return $insights;
    }

    $headers = fgetcsv($handle);
    if (!is_array($headers)) {
        fclose($handle);
        return $insights;
    }

    $issuesIdx = array_search('issues', $headers, true);
    $priorityIdx = array_search('priority_level', $headers, true);
    $conflictIdx = array_search('sitemap_indexation_conflict', $headers, true);
    $conflictReasonsIdx = array_search('sitemap_indexation_conflict_reasons', $headers, true);

    $issueCounts = [];
    $conflictReasonCounts = [];

    while (($row = fgetcsv($handle)) !== false) {
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

    $headers = fgetcsv($handle);
    if (!is_array($headers)) {
        fclose($handle);
        return $result;
    }

    $result['headers'] = array_values(array_map(static fn($h) => (string) $h, $headers));

    $rowIndex = 0;
    while (($row = fgetcsv($handle)) !== false) {
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

    $headers = fgetcsv($handle);
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

    while (($row = fgetcsv($handle)) !== false) {
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
