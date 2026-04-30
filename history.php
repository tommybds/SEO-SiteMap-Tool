<?php
declare(strict_types=1);

require __DIR__ . '/auth.php';
ensure_storage_dirs();
auth_session_start();

$user = require_user();
$isAdmin = ($user['role'] ?? '') === 'admin';

$filter = strtolower(trim((string) ($_GET['filter'] ?? '')));
if ($filter === '' || !in_array($filter, ['mine', 'all', 'anonymous'], true)) {
    $filter = $isAdmin ? 'all' : 'mine';
}
if (!$isAdmin) {
    $filter = 'mine';
}

$entries = scan_history_read(null, 1000);

if ($filter === 'mine') {
    $entries = array_values(array_filter($entries, static function ($e) use ($user) {
        return (string) ($e['user_id'] ?? '') === (string) $user['id'];
    }));
} elseif ($filter === 'anonymous') {
    $entries = array_values(array_filter($entries, static function ($e) {
        return (string) ($e['user_id'] ?? '') === '';
    }));
}

$store = users_read();
$emailById = [];
foreach ($store['users'] as $u) {
    $emailById[(string) $u['id']] = (string) $u['email'];
}

$typeLabels = [
    'sitemap_audit' => 'Sitemap',
    'mesh_audit' => 'Maillage',
    'tech_audit' => 'SEO technique',
    'security_audit' => 'Securite',
    'accessibility_audit' => 'Accessibilite',
    'images_audit' => 'Images',
    'geo_audit' => 'GEO',
];

$rows = '';
foreach ($entries as $entry) {
    $type = (string) ($entry['type'] ?? '');
    $typeLabel = $typeLabels[$type] ?? $type;
    $target = (string) ($entry['target'] ?? '');
    $ts = (string) ($entry['ts'] ?? '');
    $entryUserId = (string) ($entry['user_id'] ?? '');
    $entryEmail = $entryUserId !== '' ? ($emailById[$entryUserId] ?? '(supprime)') : '';
    $ip = (string) ($entry['ip'] ?? '');
    $jobId = (string) ($entry['job_id'] ?? '');
    $jobKind = (string) ($entry['job_kind'] ?? '');

    $userCell = $entryUserId === ''
        ? '<span class="auth-bar-pill auth-bar-pill-muted">anonyme</span>'
        : htmlspecialchars($entryEmail, ENT_QUOTES, 'UTF-8');

    $actionsCell = '';
    if ($jobId !== '' && $jobKind === 'audit') {
        $actionsCell = '<a href="preview.php?job_id=' . rawurlencode($jobId) . '">Voir</a> · <a href="download.php?job_id=' . rawurlencode($jobId) . '">CSV</a>';
    } elseif ($jobId !== '' && $jobKind === 'mesh') {
        $actionsCell = '<a href="mesh_status.php?job_id=' . rawurlencode($jobId) . '">Statut</a>';
    }

    $rows .= '<tr>'
        . '<td>' . htmlspecialchars($ts, ENT_QUOTES, 'UTF-8') . '</td>'
        . '<td><span class="history-type history-type-' . preg_replace('/[^a-z0-9_]/', '', $type) . '">' . htmlspecialchars($typeLabel, ENT_QUOTES, 'UTF-8') . '</span></td>'
        . '<td class="history-target"><span title="' . htmlspecialchars($target, ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars(mb_strimwidth($target, 0, 70, '...', 'UTF-8'), ENT_QUOTES, 'UTF-8') . '</span></td>'
        . ($isAdmin ? '<td>' . $userCell . '</td>' : '')
        . ($isAdmin ? '<td><code>' . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') . '</code></td>' : '')
        . '<td>' . $actionsCell . '</td>'
        . '</tr>';
}

if ($rows === '') {
    $colspan = $isAdmin ? 6 : 4;
    $rows = '<tr><td colspan="' . $colspan . '" class="history-empty">Aucun scan a afficher.</td></tr>';
}

$filterTabs = '';
if ($isAdmin) {
    $tabs = [
        'all' => 'Tous',
        'mine' => 'Mes scans',
        'anonymous' => 'Anonymes',
    ];
    foreach ($tabs as $key => $label) {
        $cls = $filter === $key ? 'history-filter-btn active' : 'history-filter-btn';
        $filterTabs .= '<a href="?filter=' . $key . '" class="' . $cls . '">' . $label . '</a>';
    }
    $filterTabs = '<nav class="history-filter">' . $filterTabs . '</nav>';
}

$header = $isAdmin
    ? '<tr><th>Date (UTC)</th><th>Type</th><th>Cible</th><th>Utilisateur</th><th>IP</th><th>Actions</th></tr>'
    : '<tr><th>Date (UTC)</th><th>Type</th><th>Cible</th><th>Actions</th></tr>';

$body = '<h1>Historique des scans</h1>'
    . '<p class="auth-intro">' . ($isAdmin ? 'Vue administrateur : tous les scans (utilisateurs et anonymes).' : 'Tes scans realises avec ce compte.') . '</p>'
    . $filterTabs
    . '<div class="history-table-wrap"><table class="history-table"><thead>' . $header . '</thead><tbody>' . $rows . '</tbody></table></div>'
    . '<p class="muted history-count">' . count($entries) . ' entrees affichees.</p>';

echo html_layout('Historique des scans', $body, $user);
