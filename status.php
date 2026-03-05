<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('status_poll', $ip, 240, 60);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit status atteint.',
        'retry_after' => $limit['retry_after'],
    ], 429);
}

$jobId = sanitize_job_id((string) ($_GET['job_id'] ?? ''));
if ($jobId === null) {
    respond_json(['error' => 'job_id invalide'], 400);
}

$job = read_job($jobId);
if ($job === null) {
    respond_json(['error' => 'Job introuvable'], 404);
}

$debugDetails = expose_debug_details();

$reportPath = report_path($jobId);
$conflictsPath = conflicts_report_path($jobId);
$logPath = log_path($jobId);
$reportExists = is_file($reportPath) && filesize($reportPath) > 0;
$conflictsReportExists = is_file($conflictsPath) && filesize($conflictsPath) > 0;

$currentStatus = (string) ($job['status'] ?? 'queued');
$pid = (int) ($job['pid'] ?? 0);

if (in_array($currentStatus, ['queued', 'running'], true)) {
    $running = is_process_running($pid);
    if (!$running) {
        if ($reportExists) {
            $job['status'] = 'completed';
            $job['completed_at'] = gmdate('c');
            $job['error'] = null;
        } else {
            $job['status'] = 'failed';
            $job['completed_at'] = gmdate('c');
            if ($debugDetails) {
                $tail = tail_file_lines($logPath, 15);
                $job['error'] = count($tail) > 0 ? implode("\n", $tail) : 'Le process s est arrete sans rapport.';
            } else {
                $job['error'] = 'Le process s est arrete sans rapport.';
            }
        }
        write_job($jobId, $job);
    }
}

$summary = [
    'total' => 0,
    'with_issues' => 0,
    'without_issues' => 0,
];
$insights = [
    'priority_counts' => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'none' => 0],
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
            'indexable_pct' => 0,
            'non_200_pct' => 0,
            'conflicts_pct' => 0,
        ],
        'top_sections' => [],
        'actions' => [],
    ],
];

if ((string) ($job['status'] ?? '') === 'completed' && $reportExists) {
    if (!isset($job['summary_cache']) || !is_array($job['summary_cache'])) {
        $job['summary_cache'] = build_csv_summary($reportPath);
    }
    $summary = $job['summary_cache'];
    if (
        !isset($job['insights_cache'])
        || !is_array($job['insights_cache'])
        || !isset($job['insights_cache']['domain_overview'])
        || !is_array($job['insights_cache']['domain_overview'])
    ) {
        $job['insights_cache'] = build_csv_insights($reportPath);
    }
    $insights = $job['insights_cache'];

    if (!array_key_exists('scan_diff', $job)) {
        $previous = find_previous_completed_job_for_sitemap((string) ($job['sitemap'] ?? ''), $jobId);
        if (is_array($previous)) {
            $prevJobId = (string) ($previous['job_id'] ?? '');
            $prevPath = report_path($prevJobId);
            if (is_file($prevPath)) {
                $job['scan_diff'] = [
                    'previous_job_id' => $prevJobId,
                    'previous_completed_at' => $previous['completed_at'] ?? null,
                    'diff' => build_scan_diff($reportPath, $prevPath),
                ];
            } else {
                $job['scan_diff'] = null;
            }
        } else {
            $job['scan_diff'] = null;
        }
    }

    write_job($jobId, $job);
}

$recentRuns = [];
if ($debugDetails && !empty($job['sitemap'])) {
    $recentRuns = list_recent_completed_jobs_for_sitemap((string) $job['sitemap'], 8);
}

$errorOut = $job['error'] ?? null;
if (!$debugDetails && is_string($errorOut) && trim($errorOut) !== '') {
    $errorOut = 'Le job a echoue. Active SEO_TOOL_EXPOSE_DEBUG=1 pour le detail technique.';
}

respond_json([
    'job_id' => $jobId,
    'status' => $job['status'] ?? 'unknown',
    'created_at' => $job['created_at'] ?? null,
    'started_at' => $job['started_at'] ?? null,
    'completed_at' => $job['completed_at'] ?? null,
    'sitemap' => $job['sitemap'] ?? null,
    'params' => $job['params'] ?? [],
    'error' => $errorOut,
    'report_exists' => $reportExists,
    'summary' => $summary,
    'insights' => $insights,
    'scan_diff' => $job['scan_diff'] ?? null,
    'recent_runs' => $recentRuns,
    'download_url' => 'download.php?job_id=' . rawurlencode($jobId),
    'conflicts_download_url' => 'download_conflicts.php?job_id=' . rawurlencode($jobId),
    'conflicts_report_exists' => $conflictsReportExists,
    'preview_url' => 'preview.php?job_id=' . rawurlencode($jobId),
    'log_tail' => $debugDetails ? tail_file_lines($logPath, 40) : [],
]);
