<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('audit_create', $ip, 6, 600);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit atteint. Reessaye plus tard.',
        'retry_after' => $limit['retry_after'],
    ], 429);
}

$globalActiveJobs = count_active_jobs(null);
if ($globalActiveJobs >= 12) {
    respond_json([
        'error' => 'Trop de jobs en cours sur le serveur. Reessaye dans quelques minutes.',
    ], 429);
}

$activeJobsForIp = count_active_jobs($ip);
if ($activeJobsForIp >= 2) {
    respond_json([
        'error' => 'Trop de jobs en cours pour cette IP (max 2).',
    ], 429);
}

$input = array_merge($_POST, get_json_input());
$sitemap = trim((string) ($input['sitemap'] ?? ''));

if ($sitemap === '') {
    respond_json(['error' => 'Le champ sitemap est obligatoire.'], 400);
}

$validationError = '';
if (!validate_public_url($sitemap, $validationError)) {
    respond_json(['error' => $validationError], 400);
}

$maxUrls = clamp_int($input['max_urls'] ?? 500, 1, 5000, 500);
$workers = clamp_int($input['workers'] ?? 8, 1, 32, 8);
$timeout = clamp_int($input['timeout'] ?? 15, 5, 60, 15);
$retries = clamp_int($input['retries'] ?? 2, 0, 5, 2);
$retryBackoff = clamp_float($input['retry_backoff'] ?? 0.6, 0.1, 5.0, 0.6);
$skipRobots = !empty($input['skip_robots_txt']);

$scriptPath = seo_script_path();
if (!is_file($scriptPath)) {
    respond_json(['error' => 'Script Python introuvable sur le serveur.'], 500);
}

if (!function_exists('shell_exec')) {
    respond_json(['error' => 'shell_exec est desactive sur cet hebergement.'], 500);
}

try {
    $jobId = bin2hex(random_bytes(10));
} catch (Throwable $e) {
    respond_json(['error' => 'Impossible de creer un job id.'], 500);
}

$reportPath = report_path($jobId);
$logPath = log_path($jobId);

$job = [
    'job_id' => $jobId,
    'status' => 'queued',
    'created_at' => gmdate('c'),
    'started_at' => null,
    'completed_at' => null,
    'pid' => null,
    'client_ip' => $ip,
    'sitemap' => $sitemap,
    'params' => [
        'max_urls' => $maxUrls,
        'workers' => $workers,
        'timeout' => $timeout,
        'retries' => $retries,
        'retry_backoff' => $retryBackoff,
        'skip_robots_txt' => $skipRobots,
    ],
    'report_path' => $reportPath,
    'log_path' => $logPath,
    'error' => null,
];

if (!write_job($jobId, $job)) {
    respond_json(['error' => 'Impossible d ecrire le fichier job.'], 500);
}

$args = [
    '--sitemap ' . escapeshellarg($sitemap),
    '--output ' . escapeshellarg($reportPath),
    '--max-urls ' . escapeshellarg((string) $maxUrls),
    '--workers ' . escapeshellarg((string) $workers),
    '--timeout ' . escapeshellarg((string) $timeout),
    '--retries ' . escapeshellarg((string) $retries),
    '--retry-backoff ' . escapeshellarg((string) $retryBackoff),
];

if ($skipRobots) {
    $args[] = '--skip-robots-txt';
}

$command = 'nohup python3 ' . escapeshellarg($scriptPath)
    . ' ' . implode(' ', $args)
    . ' > ' . escapeshellarg($logPath)
    . ' 2>&1 & echo $!';

$pidRaw = shell_exec($command);
$pid = (int) trim((string) $pidRaw);

if ($pid <= 0) {
    $job['status'] = 'failed';
    $job['error'] = 'Impossible de demarrer le process Python.';
    $job['completed_at'] = gmdate('c');
    write_job($jobId, $job);
    respond_json(['error' => 'Le process Python n a pas pu demarrer.'], 500);
}

$job['status'] = 'running';
$job['started_at'] = gmdate('c');
$job['pid'] = $pid;
write_job($jobId, $job);

respond_json([
    'job_id' => $jobId,
    'status' => 'running',
    'status_url' => 'status.php?job_id=' . rawurlencode($jobId),
    'download_url' => 'download.php?job_id=' . rawurlencode($jobId),
    'preview_url' => 'preview.php?job_id=' . rawurlencode($jobId),
]);
