<?php
declare(strict_types=1);

require __DIR__ . '/auth.php';
ensure_storage_dirs();
auth_session_start();

$admin = require_admin();

$flash = '';
$flashKind = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_check((string) ($_POST['_csrf'] ?? ''))) {
        $flash = 'Jeton CSRF invalide.';
        $flashKind = 'error';
    } else {
        $action = (string) ($_POST['action'] ?? '');
        $targetId = (string) ($_POST['user_id'] ?? '');

        if ($targetId === $admin['id'] && in_array($action, ['delete', 'disable', 'demote'], true)) {
            $flash = 'Tu ne peux pas effectuer cette action sur ton propre compte.';
            $flashKind = 'error';
        } else {
            $store = users_read();
            $target = users_find_by_id($store, $targetId);
            if ($target === null) {
                $flash = 'Utilisateur introuvable.';
                $flashKind = 'error';
            } else {
                switch ($action) {
                    case 'approve':
                        user_update($targetId, static function (array $u) use ($admin): array {
                            $u['status'] = 'active';
                            $u['approved_at'] = gmdate('c');
                            $u['approved_by'] = $admin['id'];
                            return $u;
                        });
                        $flash = 'Compte approuve.';
                        $flashKind = 'success';
                        break;

                    case 'disable':
                        user_update($targetId, static function (array $u): array {
                            $u['status'] = 'disabled';
                            return $u;
                        });
                        $flash = 'Compte desactive.';
                        $flashKind = 'success';
                        break;

                    case 'enable':
                        user_update($targetId, static function (array $u): array {
                            $u['status'] = 'active';
                            return $u;
                        });
                        $flash = 'Compte reactive.';
                        $flashKind = 'success';
                        break;

                    case 'promote':
                        user_update($targetId, static function (array $u): array {
                            $u['role'] = 'admin';
                            return $u;
                        });
                        $flash = 'Utilisateur promu administrateur.';
                        $flashKind = 'success';
                        break;

                    case 'demote':
                        $store2 = users_read();
                        if (users_count_active_admins($store2) <= 1 && ($target['role'] ?? '') === 'admin') {
                            $flash = 'Impossible de retirer le dernier administrateur actif.';
                            $flashKind = 'error';
                        } else {
                            user_update($targetId, static function (array $u): array {
                                $u['role'] = 'user';
                                return $u;
                            });
                            $flash = 'Role retrograde en utilisateur.';
                            $flashKind = 'success';
                        }
                        break;

                    case 'delete':
                        $store2 = users_read();
                        if (($target['role'] ?? '') === 'admin' && users_count_active_admins($store2) <= 1) {
                            $flash = 'Impossible de supprimer le dernier administrateur.';
                            $flashKind = 'error';
                        } else {
                            user_delete($targetId);
                            $flash = 'Compte supprime.';
                            $flashKind = 'success';
                        }
                        break;

                    case 'reject':
                        if (($target['status'] ?? '') === 'pending') {
                            user_delete($targetId);
                            $flash = 'Inscription rejetee.';
                            $flashKind = 'success';
                        } else {
                            $flash = 'Action reservee aux comptes en attente.';
                            $flashKind = 'error';
                        }
                        break;

                    default:
                        $flash = 'Action inconnue.';
                        $flashKind = 'error';
                }
            }
        }
    }
}

$store = users_read();
$users = $store['users'];

usort($users, static function (array $a, array $b): int {
    $statusOrder = ['pending' => 0, 'active' => 1, 'disabled' => 2];
    $aOrder = $statusOrder[$a['status'] ?? ''] ?? 9;
    $bOrder = $statusOrder[$b['status'] ?? ''] ?? 9;
    if ($aOrder !== $bOrder) {
        return $aOrder <=> $bOrder;
    }
    return strcmp((string) ($b['created_at'] ?? ''), (string) ($a['created_at'] ?? ''));
});

$flashBlock = '';
if ($flash !== '') {
    $cls = $flashKind === 'error' ? 'auth-alert-error' : 'auth-alert-success';
    $flashBlock = '<div class="auth-alert ' . $cls . '">' . htmlspecialchars($flash, ENT_QUOTES, 'UTF-8') . '</div>';
}

$rows = '';
$csrf = csrf_field();
foreach ($users as $u) {
    $id = (string) ($u['id'] ?? '');
    $email = (string) ($u['email'] ?? '');
    $role = (string) ($u['role'] ?? 'user');
    $status = (string) ($u['status'] ?? '');
    $created = (string) ($u['created_at'] ?? '');
    $lastLogin = (string) ($u['last_login_at'] ?? '');
    $isSelf = $id === $admin['id'];

    $statusPill = '<span class="auth-bar-pill auth-bar-pill-' . $status . '">' . htmlspecialchars($status, ENT_QUOTES, 'UTF-8') . '</span>';
    $rolePill = '<span class="auth-bar-pill">' . htmlspecialchars($role, ENT_QUOTES, 'UTF-8') . '</span>';

    $actions = [];
    if ($status === 'pending') {
        $actions[] = '<button name="action" value="approve">Approuver</button>';
        $actions[] = '<button name="action" value="reject" class="danger">Rejeter</button>';
    }
    if ($status === 'active' && !$isSelf) {
        $actions[] = '<button name="action" value="disable">Desactiver</button>';
    }
    if ($status === 'disabled') {
        $actions[] = '<button name="action" value="enable">Reactiver</button>';
    }
    if ($role !== 'admin' && $status === 'active') {
        $actions[] = '<button name="action" value="promote">Promouvoir admin</button>';
    }
    if ($role === 'admin' && !$isSelf) {
        $actions[] = '<button name="action" value="demote">Retrograder</button>';
    }
    if (!$isSelf && $status !== 'pending') {
        $actions[] = '<button name="action" value="delete" class="danger" onclick="return confirm(\'Supprimer definitivement ce compte ?\');">Supprimer</button>';
    }

    $actionsHtml = '';
    if (count($actions) > 0) {
        $actionsHtml = '<form method="post" class="admin-actions">' . $csrf
            . '<input type="hidden" name="user_id" value="' . htmlspecialchars($id, ENT_QUOTES, 'UTF-8') . '">'
            . implode(' ', $actions)
            . '</form>';
    }

    $rows .= '<tr>'
        . '<td>' . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . ($isSelf ? ' <em>(toi)</em>' : '') . '</td>'
        . '<td>' . $rolePill . '</td>'
        . '<td>' . $statusPill . '</td>'
        . '<td>' . htmlspecialchars($created, ENT_QUOTES, 'UTF-8') . '</td>'
        . '<td>' . htmlspecialchars($lastLogin !== '' ? $lastLogin : '-', ENT_QUOTES, 'UTF-8') . '</td>'
        . '<td>' . $actionsHtml . '</td>'
        . '</tr>';
}

if ($rows === '') {
    $rows = '<tr><td colspan="6" class="history-empty">Aucun compte.</td></tr>';
}

$body = '<h1>Administration des comptes</h1>'
    . '<p class="auth-intro">Approuve les inscriptions, gere les roles et les acces.</p>'
    . $flashBlock
    . '<div class="history-table-wrap"><table class="history-table">'
    . '<thead><tr><th>Email</th><th>Role</th><th>Statut</th><th>Cree</th><th>Derniere connexion</th><th>Actions</th></tr></thead>'
    . '<tbody>' . $rows . '</tbody></table></div>';

echo html_layout('Administration des comptes', $body, $admin);
