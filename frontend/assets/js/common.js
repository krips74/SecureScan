// ═══════════════════════════════════════════════════════════
//  SecureScan common.js — Auth guard + Sidebar injection
// ═══════════════════════════════════════════════════════════

const API = '';  // same origin

// ── AUTH GUARD ────────────────────────────────────────────
(function authGuard() {
  const publicPages = ['home', 'login', 'register', ''];
  const page = location.pathname.split('/').pop().replace('.html', '');
  if (publicPages.includes(page || '')) return;
  if (publicPages.includes(page)) return;

  const token = localStorage.getItem('ss_token');
  if (!token) {
    window.location.href = '/login';
    return;
  }

  // Decode JWT expiry (without lib)
  try {
    const parts = token.split('.');
    const payload = JSON.parse(atob(parts[1]));

    // Admins are not normal users; they must use the admin control panel.
    if ((payload.role || '').toString().toLowerCase() === 'admin') {
      clearAuth();
      window.location.href = '/admin_dashboard';
      return;
    }

    if (payload.exp && payload.exp * 1000 < Date.now()) {
      logout();
    }
  } catch (e) {
    /* malformed token */
    logout();
  }
})();

function getToken()    { return localStorage.getItem('ss_token') || ''; }
function getUsername() { return localStorage.getItem('ss_user') || 'User'; }
function getRole()     { return localStorage.getItem('ss_role') || 'user'; }
function getEmail()    { return localStorage.getItem('ss_email') || ''; }

function authHeaders() {
  return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + getToken() };
}

function clearAuth() {
  localStorage.removeItem('ss_token');
  localStorage.removeItem('ss_user');
  localStorage.removeItem('ss_email');
  localStorage.removeItem('ss_role');
}

async function logout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST', headers: authHeaders() });
  } catch (e) {
    // ignore network errors on logout
  } finally {
    clearAuth();
    window.location.href = '/home';
  }
}

// ── SAFE DOM HELPERS ───────────────────────────────────────
function clearChildren(node) {
  while (node && node.firstChild) node.removeChild(node.firstChild);
}

function el(tag, options = {}) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text != null) node.textContent = String(options.text);
  if (options.attrs) {
    for (const [k, v] of Object.entries(options.attrs)) {
      if (v == null) continue;
      node.setAttribute(k, String(v));
    }
  }
  return node;
}

function badgeEl(text, variant) {
  const span = el('span', { className: `badge badge-${variant || 'muted'}` });
  span.textContent = String(text ?? '—');
  return span;
}

function severityBadgeEl(sev) {
  const map = {
    critical: 'danger',  high:   'danger',
    medium:   'warning', low:    'info',
    info:     'muted',   clean:  'success'
  };
  const s = (sev || '—').toString().toLowerCase();
  const variant = map[s] || 'muted';
  return badgeEl((sev || '—').toString().toUpperCase(), variant);
}

// ── SIDEBAR ───────────────────────────────────────────────
const NAV_ITEMS = [
  { label: 'Dashboard',        href: '/dashboard',           section: 'main' },
  { label: 'Scan',             href: '/scan_all',        section: 'main' },
  { label: 'Reports',          href: '/reports',         section: 'main' },
  { label: 'XSS Scanner',      href: '/scan',            section: 'tools' },
  { label: 'SQL Injection',    href: '/sql_injection',   section: 'tools' },
  { label: 'CORS Tester',      href: '/cors_scan',       section: 'tools' },
  { label: 'Open Redirect',    href: '/open_redirect',   section: 'tools' },
  { label: 'Header Analysis',  href: '/header_scan',     section: 'tools' },
  { label: 'Phishing Scanner', href: '/phishing',         section: 'tools' },
  { label: 'Advanced Scan',    href: '/advanced_scan',   section: 'tools' },
  { label: 'Feedback',         href: '/feedback',        section: 'support' },
];

function getSidebarCollapsed() {
  return localStorage.getItem('ss_sidebar_collapsed') === '1';
}

function setSidebarCollapsed(collapsed) {
  localStorage.setItem('ss_sidebar_collapsed', collapsed ? '1' : '0');
}

function iconSvg(kind) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  svg.classList.add('nav-svg');

  const p = document.createElementNS(ns, 'path');
  p.setAttribute('fill', 'none');
  p.setAttribute('stroke', 'currentColor');
  p.setAttribute('stroke-width', '1.8');
  p.setAttribute('stroke-linecap', 'round');
  p.setAttribute('stroke-linejoin', 'round');

  // Simple, custom line-icons (no external libraries).
  const dMap = {
    dashboard: 'M4 13.5V20h6v-6.5H4z M14 4h6v7h-6V4z M14 13h6v7h-6v-7z M4 4h6v7H4V4z',
    reports: 'M7 4h7l3 3v13H7V4z M14 4v3h3',
    scan: 'M12 12m-8 0a8 8 0 1 0 16 0a8 8 0 1 0-16 0 M12 12m-5 0a5 5 0 1 0 10 0a5 5 0 1 0-10 0 M12 12m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0 M12 12m-.8 0a.8.8 0 1 0 1.6 0a.8.8 0 1 0-1.6 0',
    feedback: 'M21 15a4 4 0 0 1-4 4H8l-5 3 1.5-5.5A4 4 0 0 1 3 15V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4v8z',
    xss: 'M8 8l-3 4 3 4 M16 8l3 4-3 4 M13 7l-2 10',
    sqli: 'M7 7c0-1.7 2.2-3 5-3s5 1.3 5 3-2.2 3-5 3-5-1.3-5-3z M7 7v10c0 1.7 2.2 3 5 3s5-1.3 5-3V7',
    cors: 'M12 3c4.97 0 9 4.03 9 9s-4.03 9-9 9-9-4.03-9-9 4.03-9 9-9z M3 12h18 M12 3c2.5 2.6 4 5.7 4 9s-1.5 6.4-4 9 M12 3c-2.5 2.6-4 5.7-4 9s1.5 6.4 4 9',
     redirect: 'M7 7h6a4 4 0 0 1 0 8H8 M13 9l3-2-3-2',
    headers: 'M6 7h12 M6 12h12 M6 17h8',
    idor: 'M12 2l8 3v7c0 5.55-3.84 10.74-9 12-5.16-1.26-9-6.45-9-12V5l8-3z',
     advanced: 'M12 3v3 M12 18v3 M4.2 7.2l2.1 2.1 M17.7 14.7l2.1 2.1 M3 12h3 M18 12h3 M4.2 16.8l2.1-2.1 M17.7 9.3l2.1-2.1 M12 8a4 4 0 1 0 0 8a4 4 0 0 0 0-8z',
    phishing: 'M4 4l16 16 M12 3c-3 0-5.5 1.5-7 4 2 3.5 5 6 7 6s5-2.5 7-6c-1.5-2.5-4-4-7-4-3 0-5.5 2-7 5 2 3 4.5 5 7 5s5-2 7-5c-2-3-4-5-7-5z',
  };

  p.setAttribute('d', dMap[kind] || dMap.dashboard);
  svg.appendChild(p);
  return svg;
}

function navIconKind(itemHref) {
  switch (itemHref) {
    case '/dashboard': return 'dashboard';
    case '/scan_all': return 'scan';
    case '/reports': return 'reports';
    case '/feedback': return 'feedback';
    case '/scan': return 'xss';
    case '/sql_injection': return 'sqli';
    case '/cors_scan': return 'cors';
    case '/open_redirect': return 'redirect';
    case '/header_scan': return 'headers';
    case '/advanced_scan': return 'advanced';
     case '/phishing': return 'phishing';
     default: return 'dashboard';
  }
}

function buildSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;

  const currentPage = location.pathname.split('/').pop().replace('.html', '') || 'index';
  const user = getUsername();
  const email = getEmail();
  const role = getRole();
  const initial = user[0].toUpperCase();

  const mainItems = NAV_ITEMS.filter(n => n.section === 'main');
  const toolItems = NAV_ITEMS.filter(n => n.section === 'tools');
  const supportItems = NAV_ITEMS.filter(n => n.section === 'support');

  function renderLinks(container, items) {
    for (const item of items) {
      const a = el('a', { attrs: { href: item.href } });
      if (currentPage === item.href) a.classList.add('active');
      const iconWrap = el('span', { className: 'nav-icon' });
      iconWrap.appendChild(iconSvg(navIconKind(item.href)));
      a.appendChild(iconWrap);
      a.appendChild(document.createTextNode(item.label));
      container.appendChild(a);
    }
  }

  clearChildren(sidebar);

  if (getSidebarCollapsed()) sidebar.classList.add('is-collapsed');

  // Collapse mode (hamburger toggle) has been disabled in favor of explicit
  // Hide/Show sidebar. Keep the stored value but do not apply it.

  const header = el('div', { className: 'sidebar-header' });
  const logo = el('a', { className: 'sidebar-logo', attrs: { href: '/dashboard' } });
  const logoIcon = el('div', { className: 'logo-icon' });
  const logoImg = el('img', { attrs: { src: 'assets/images/logo.svg', alt: 'SecureScan' } });
  logoIcon.appendChild(logoImg);
  logo.appendChild(logoIcon);
  const logoTextWrap = el('div', { className: 'logo-text-wrap' });
  logoTextWrap.appendChild(el('div', { className: 'logo-text', text: 'SecureScan' }));
  logo.appendChild(logoTextWrap);
  header.appendChild(logo);

  const toggleBtn = el('button', {
    className: 'sidebar-toggle',
    attrs: { type: 'button', 'aria-label': 'Toggle sidebar' }
  });
  toggleBtn.appendChild(el('span', { className: 'hamburger' }));
  toggleBtn.addEventListener('click', () => {
    const collapsed = !sidebar.classList.contains('is-collapsed');
    sidebar.classList.toggle('is-collapsed', collapsed);
    document.documentElement.classList.toggle('sidebar-collapsed', collapsed);
    setSidebarCollapsed(collapsed);
  });
  header.appendChild(toggleBtn);
  sidebar.appendChild(header);

  const mainSection = el('div', { className: 'sidebar-section' });
  mainSection.appendChild(el('div', { className: 'sidebar-section-label', text: 'Main' }));
  const mainNav = el('nav', { className: 'sidebar-nav' });
  renderLinks(mainNav, mainItems);
  mainSection.appendChild(mainNav);
  sidebar.appendChild(mainSection);

  const toolSection = el('div', { className: 'sidebar-section' });
  toolSection.appendChild(el('div', { className: 'sidebar-section-label', text: 'Security Tools' }));
  const toolNav = el('nav', { className: 'sidebar-nav' });
  renderLinks(toolNav, toolItems);
  toolSection.appendChild(toolNav);
  sidebar.appendChild(toolSection);

  if (supportItems.length) {
    const supportSection = el('div', { className: 'sidebar-section' });
    supportSection.appendChild(el('div', { className: 'sidebar-section-label', text: 'Support' }));
    const supportNav = el('nav', { className: 'sidebar-nav' });
    renderLinks(supportNav, supportItems);
    supportSection.appendChild(supportNav);
    sidebar.appendChild(supportSection);
  }

  const footer = el('div', { className: 'sidebar-footer' });

  const logoutBtn = el('button', {
    className: 'btn btn-secondary sidebar-logout',
    text: 'Logout',
    attrs: { type: 'button' }
  });
  logoutBtn.addEventListener('click', logout);
  footer.appendChild(logoutBtn);

  const userBtn = el('div', { className: 'sidebar-user' });
  userBtn.appendChild(el('div', { className: 'avatar', text: initial }));
  const info = el('div', { className: 'user-info' });
  info.appendChild(el('div', { className: 'username', text: user }));
  if (email) info.appendChild(el('div', { className: 'role', text: email }));
  userBtn.appendChild(info);
  footer.appendChild(userBtn);
  sidebar.appendChild(footer);
}

// ── TOAST ─────────────────────────────────────────────────
function showToast(msg, type = 'success', duration = 3500) {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), duration);
}

// ── UTILITY ───────────────────────────────────────────────
function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

// ── INIT ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.documentElement.classList.toggle('sidebar-collapsed', getSidebarCollapsed());
  buildSidebar();
});
