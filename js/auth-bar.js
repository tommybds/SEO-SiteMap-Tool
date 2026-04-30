(function () {
  const bar = document.getElementById('auth-bar');
  if (!bar) return;

  function escape(value) {
    return String(value || '').replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  fetch('me.php', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (data) {
      if (!data) return;

      if (data.authenticated && data.user) {
        const u = data.user;
        const isAdmin = u.role === 'admin';
        const csrf = escape(data.csrf || '');
        bar.innerHTML =
          '<span class="auth-bar-user">' + escape(u.email) +
            (isAdmin ? ' <span class="auth-bar-pill">admin</span>' : '') +
          '</span>' +
          '<a href="history.php">Historique</a>' +
          (isAdmin ? '<a href="admin_users.php">Administration</a>' : '') +
          '<form method="post" action="logout.php" class="auth-bar-logout">' +
            '<input type="hidden" name="_csrf" value="' + csrf + '">' +
            '<button type="submit" class="auth-bar-link">Se deconnecter</button>' +
          '</form>';
      } else {
        bar.innerHTML =
          '<a href="login.php">Se connecter</a>' +
          '<a href="register.php">Creer un compte</a>';
      }
      bar.hidden = false;
    })
    .catch(function () { /* silent */ });
})();
