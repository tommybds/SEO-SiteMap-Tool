<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();
@ini_set('max_execution_time', '0');
@set_time_limit(0);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('mesh_run', $ip, 12, 600);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit maillage atteint. Reessaye plus tard.',
        'retry_after' => $limit['retry_after'],
    ], 429);
}

$globalActiveJobs = count_active_jobs(null) + count_active_mesh_jobs(null);
if ($globalActiveJobs >= 12) {
    respond_json([
        'error' => 'Trop de jobs en cours sur le serveur. Reessaye dans quelques minutes.',
    ], 429);
}

$activeMeshJobsForIp = count_active_mesh_jobs($ip);
if ($activeMeshJobsForIp >= 2) {
    respond_json([
        'error' => 'Trop de jobs maillage en cours pour cette IP (max 2).',
    ], 429);
}

$input = array_merge($_POST, get_json_input());
$startUrl = trim((string) ($input['start_url'] ?? ''));
if ($startUrl === '') {
    respond_json(['error' => 'Le champ start_url est obligatoire.'], 400);
}

$validationError = '';
if (!validate_public_url($startUrl, $validationError)) {
    respond_json(['error' => $validationError], 400);
}

$maxPages = clamp_int($input['max_pages'] ?? 80, 10, 300, 80);
$timeout = clamp_int($input['timeout'] ?? 12, 3, 30, 12);
$maxEdges = clamp_int($input['max_edges'] ?? 800, 100, 2000, 800);
$maxRuntimeMs = clamp_int($input['max_runtime_ms'] ?? 60000, 15000, 120000, 60000);

$scriptPath = internal_mesh_script_path();
if (!is_file($scriptPath)) {
    respond_json(['error' => 'Script maillage introuvable sur le serveur.'], 500);
}

if (!function_exists('shell_exec')) {
    respond_json(['error' => 'shell_exec est desactive sur cet hebergement.'], 500);
}

try {
    $jobId = bin2hex(random_bytes(10));
} catch (Throwable $e) {
    respond_json(['error' => 'Impossible de creer un job maillage id.'], 500);
}

$outputPath = mesh_output_path($jobId);
$progressPath = mesh_progress_path($jobId);
$logPath = mesh_log_path($jobId);

$job = [
    'job_id' => $jobId,
    'status' => 'queued',
    'created_at' => gmdate('c'),
    'started_at' => null,
    'completed_at' => null,
    'pid' => null,
    'client_ip' => $ip,
    'start_url' => $startUrl,
    'params' => [
        'max_pages' => $maxPages,
        'timeout' => $timeout,
        'max_edges' => $maxEdges,
        'max_runtime_ms' => $maxRuntimeMs,
    ],
    'output_path' => $outputPath,
    'progress_path' => $progressPath,
    'log_path' => $logPath,
    'mesh_id' => null,
    'error' => null,
];

if (!write_mesh_job($jobId, $job)) {
    respond_json(['error' => 'Impossible d ecrire le fichier job maillage.'], 500);
}

$command = 'nohup python3 ' . escapeshellarg($scriptPath)
    . ' --start-url ' . escapeshellarg($startUrl)
    . ' --max-pages ' . escapeshellarg((string) $maxPages)
    . ' --timeout ' . escapeshellarg((string) $timeout)
    . ' --max-edges ' . escapeshellarg((string) $maxEdges)
    . ' --max-runtime-ms ' . escapeshellarg((string) $maxRuntimeMs)
    . ' --output-json ' . escapeshellarg($outputPath)
    . ' --progress-json ' . escapeshellarg($progressPath)
    . ' > ' . escapeshellarg($logPath)
    . ' 2>&1 & echo $!';

$pidRaw = shell_exec($command);
$pid = (int) trim((string) $pidRaw);

if ($pid <= 0) {
    $job['status'] = 'failed';
    $job['completed_at'] = gmdate('c');
    $job['error'] = 'Impossible de demarrer le process maillage.';
    write_mesh_job($jobId, $job);
    respond_json(['error' => 'Le process maillage n a pas pu demarrer.'], 500);
}

$job['status'] = 'running';
$job['started_at'] = gmdate('c');
$job['pid'] = $pid;
write_mesh_job($jobId, $job);

respond_json([
    'job_id' => $jobId,
    'status' => 'running',
    'status_url' => 'mesh_status.php?job_id=' . rawurlencode($jobId),
]);
