<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
ensure_storage_dirs();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    respond_json(['error' => 'Method not allowed'], 405);
}

$ip = client_ip();
$limit = enforce_rate_limit('mesh_status_poll', $ip, 240, 60);
if (!$limit['allowed']) {
    respond_json([
        'error' => 'Rate limit status maillage atteint.',
        'retry_after' => $limit['retry_after'],
    ], 429);
}

$jobId = sanitize_job_id((string) ($_GET['job_id'] ?? ''));
if ($jobId === null) {
    respond_json(['error' => 'job_id invalide'], 400);
}

$job = read_mesh_job($jobId);
if ($job === null) {
    respond_json(['error' => 'Job maillage introuvable'], 404);
}

$debugDetails = expose_debug_details();

$outputPath = mesh_output_path($jobId);
$progressPath = mesh_progress_path($jobId);
$logPath = mesh_log_path($jobId);

$progress = null;
if (is_file($progressPath)) {
    $rawProgress = file_get_contents($progressPath);
    $decodedProgress = json_decode((string) $rawProgress, true);
    if (is_array($decodedProgress)) {
        $progress = $decodedProgress;
    }
}

$currentStatus = (string) ($job['status'] ?? 'queued');
$pid = (int) ($job['pid'] ?? 0);

if (in_array($currentStatus, ['queued', 'running'], true)) {
    $running = is_process_running($pid);
    if (!$running) {
        $rawOutput = is_file($outputPath) ? (string) file_get_contents($outputPath) : '';
        $decoded = json_decode($rawOutput, true);

        if (is_array($decoded) && !empty($decoded['ok']) && is_array($decoded['mesh'] ?? null)) {
            $mesh = $decoded['mesh'];
            $meshId = (string) ($job['mesh_id'] ?? '');
            if (!preg_match('/^[a-f0-9]{20}$/i', $meshId)) {
                try {
                    $meshId = bin2hex(random_bytes(10));
                } catch (Throwable $e) {
                    $meshId = substr(sha1((string) microtime(true) . $jobId), 0, 20);
                }
            }

            $stored = [
                'mesh_id' => $meshId,
                'created_at' => gmdate('c'),
                'start_url' => $job['start_url'] ?? null,
                'params' => $job['params'] ?? [],
                'mesh' => $mesh,
            ];
            if (write_mesh_result($meshId, $stored)) {
                $job['mesh_id'] = $meshId;
                $job['status'] = 'completed';
                $job['completed_at'] = gmdate('c');
                $job['error'] = null;
            } else {
                $job['status'] = 'failed';
                $job['completed_at'] = gmdate('c');
                $job['error'] = 'Impossible d enregistrer le resultat maillage.';
            }
        } else {
            $job['status'] = 'failed';
            $job['completed_at'] = gmdate('c');
            $err = is_array($decoded) ? trim((string) ($decoded['error'] ?? '')) : '';
            if ($err === '') {
                if ($debugDetails) {
                    $tail = tail_file_lines($logPath, 20);
                    $err = count($tail) > 0 ? implode("\n", $tail) : 'Le process maillage s est arrete sans resultat JSON.';
                } else {
                    $err = 'Le process maillage s est arrete sans resultat JSON.';
                }
            }
            $job['error'] = $err;
        }

        write_mesh_job($jobId, $job);
    }
}

$meshId = sanitize_job_id((string) ($job['mesh_id'] ?? ''));
$mesh = null;
if ((string) ($job['status'] ?? '') === 'completed' && $meshId !== null) {
    $stored = read_mesh_result($meshId);
    if (is_array($stored) && is_array($stored['mesh'] ?? null)) {
        $mesh = $stored['mesh'];
        if ($progress === null) {
            $progress = [
                'stage' => 'completed',
                'progress_pct' => 100,
                'pages_scanned' => (int) ($mesh['pages_scanned'] ?? 0),
                'pages_target' => (int) (($job['params']['max_pages'] ?? 0)),
                'queue_size' => 0,
                'edges_found' => (int) ($mesh['edges_count'] ?? 0),
                'elapsed_ms' => (int) ($mesh['elapsed_ms'] ?? 0),
                'runtime_budget_ms' => (int) ($mesh['runtime_budget_ms'] ?? 0),
                'runtime_limited' => (bool) ($mesh['runtime_limited'] ?? false),
                'seed_mode' => (string) ($mesh['seed_mode'] ?? 'crawl_only'),
            ];
        }
    }
}

$errorOut = $job['error'] ?? null;
if (!$debugDetails && is_string($errorOut) && trim($errorOut) !== '') {
    $errorOut = 'Le job maillage a echoue. Active SEO_TOOL_EXPOSE_DEBUG=1 pour le detail technique.';
}

respond_json([
    'job_id' => $jobId,
    'status' => $job['status'] ?? 'unknown',
    'created_at' => $job['created_at'] ?? null,
    'started_at' => $job['started_at'] ?? null,
    'completed_at' => $job['completed_at'] ?? null,
    'start_url' => $job['start_url'] ?? null,
    'params' => $job['params'] ?? [],
    'error' => $errorOut,
    'mesh_id' => $meshId,
    'mesh' => $mesh,
    'progress' => $progress,
    'log_tail' => $debugDetails ? tail_file_lines($logPath, 40) : [],
]);
