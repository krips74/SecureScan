// ═══════════════════════════════════════════════════════════
//  SecureScan admin_common.js — Admin auth guard + Sidebar
// ═══════════════════════════════════════════════════════════

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

function adminFetch(url, options = {}) {
  const opts = Object.assign({
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin'
  }, options);
  opts.headers = Object.assign({ 'Content-Type': 'application/json' }, (options.headers || {}));
  return fetch(url, opts);
}

async function adminMe() {
  const res = await adminFetch('/api/admin/me', { method: 'GET' });
  if (!res.ok) return null;
  const data = await res.json();
  if (!data || data.success !== true) return null;
  return data;
}

async function adminLogout() {
  try {
    await adminFetch('/api/admin/logout', { method: 'POST' });
  } catch (e) {
    // ignore
  } finally {
    window.location.href = '/login';
  }
}

(function adminAuthGuard() {
  const publicPages = ['login', 'admin_login'];
  const page = location.pathname.split('/').pop().replace('.html', '') || '';
  if (publicPages.includes(page)) return;

  adminMe().then((me) => {
    if (!me) window.location.href = '/login';
  }).catch(() => {
    window.location.href = '/login';
  });
})();

const ADMIN_NAV = [
  { label: 'Control Center', href: '/admin_dashboard' },
  { label: 'Users',          href: '/admin_users' },
  { label: 'Scan Monitor',   href: '/admin_scans' },
  { label: 'Vulnerabilities',href: '/admin_vulnerabilities' },
  { label: 'Feedback',       href: '/admin_feedback' },
];

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

  const dMap = {
    dashboard: 'M4 13.5V20h6v-6.5H4z M14 4h6v7h-6V4z M14 13h6v7h-6v-7z M4 4h6v7H4V4z',
    users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M16 3.5a4 4 0 0 1 0 8 M20 21v-2a4 4 0 0 0-3-3.9 M12 7a4 4 0 1 1-8 0a4 4 0 0 1 8 0z',
    scans: 'M12 12m-8 0a8 8 0 1 0 16 0a8 8 0 1 0-16 0 M12 12m-5 0a5 5 0 1 0 10 0a5 5 0 1 0-10 0',
    vulns: 'M12 2l7 4v6c0 5-3 9-7 10c-4-1-7-5-7-10V6l7-4z M9 12h6 M12 9v6',
    feedback: 'M21 15a4 4 0 0 1-4 4H8l-5 3 1.5-5.5A4 4 0 0 1 3 15V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4v8z',
    logout: 'M10 17l-1 1H4V6h5l1 1 M15 12H7 M15 12l-2-2 M15 12l-2 2 M20 6v12',
  };

  p.setAttribute('d', dMap[kind] || dMap.dashboard);
  svg.appendChild(p);
  return svg;
}

function navIconKind(href) {
  switch (href) {
    case '/admin_dashboard': return 'dashboard';
    case '/admin_users': return 'users';
    case '/admin_scans': return 'scans';
    case '/admin_vulnerabilities': return 'vulns';
    case '/admin_feedback': return 'feedback';
    default: return 'dashboard';
  }
}

function buildAdminSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;

  const currentPage = location.pathname.split('/').pop().replace('.html', '') || 'admin_dashboard';
  clearChildren(sidebar);

  const header = el('div', { className: 'sidebar-header' });
  const logo = el('a', { className: 'sidebar-logo', attrs: { href: '/admin_dashboard' } });
  const logoIcon = el('div', { className: 'logo-icon' });
  logoIcon.appendChild(el('img', { attrs: { src: 'assets/images/logo.svg', alt: 'SecureScan' } }));
  logo.appendChild(logoIcon);
  const logoTextWrap = el('div', { className: 'logo-text-wrap' });
  logoTextWrap.appendChild(el('div', { className: 'logo-text', text: 'SecureScan' }));
  logoTextWrap.appendChild(el('div', { className: 'logo-subtext', text: 'Admin' }));
  logo.appendChild(logoTextWrap);
  header.appendChild(logo);
  sidebar.appendChild(header);

  const nav = el('nav', { className: 'sidebar-nav' });
  for (const item of ADMIN_NAV) {
    const a = el('a', { attrs: { href: item.href } });
    if (currentPage === item.href) a.classList.add('active');
    const iconWrap = el('span', { className: 'nav-icon' });
    iconWrap.appendChild(iconSvg(navIconKind(item.href)));
    a.appendChild(iconWrap);
    a.appendChild(document.createTextNode(item.label));
    nav.appendChild(a);
  }

  const logoutBtn = el('button', { className: 'btn btn-secondary', text: 'Logout', attrs: { type: 'button', style: 'margin-top:12px; width:100%;' } });
  logoutBtn.addEventListener('click', adminLogout);
  nav.appendChild(logoutBtn);

  sidebar.appendChild(nav);
}

(function initAdminSidebar() {
  // Ensure sidebar is always visible on admin pages.
  try { localStorage.removeItem('ss_admin_sidebar_hidden'); } catch (e) {}
  document.documentElement.classList.remove('sidebar-hidden');
  buildAdminSidebar();
})();

function drawBarChart(canvas, items, options = {}) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const width = canvas.width = canvas.clientWidth * (window.devicePixelRatio || 1);
  const height = canvas.height = canvas.clientHeight * (window.devicePixelRatio || 1);
  ctx.clearRect(0, 0, width, height);

  const padding = 28 * (window.devicePixelRatio || 1);
  const maxCount = Math.max(1, ...items.map(i => Number(i.count || 0)));
  const barW = Math.max(10, (width - padding * 2) / Math.max(1, items.length) - 10);
  const gap = 10 * (window.devicePixelRatio || 1);

  const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#22d3ee';
  const muted = getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim() || '#64748b';

  ctx.fillStyle = muted;
  ctx.font = `${12 * (window.devicePixelRatio || 1)}px sans-serif`;

  items.forEach((it, idx) => {
    const x = padding + idx * (barW + gap);
    const v = Number(it.count || 0);
    const h = Math.max(2, (height - padding * 2) * (v / maxCount));
    const y = height - padding - h;

    ctx.fillStyle = accent;
    ctx.fillRect(x, y, barW, h);

    ctx.fillStyle = muted;
    const label = (it.type || '').toString().toUpperCase();
    ctx.save();
    ctx.translate(x + barW / 2, height - padding + 8 * (window.devicePixelRatio || 1));
    ctx.rotate(-Math.PI / 6);
    ctx.textAlign = 'center';
    ctx.fillText(label, 0, 0);
    ctx.restore();
  });
}

function drawLineChart(canvas, points) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const dpr = (window.devicePixelRatio || 1);
  const width = canvas.width = canvas.clientWidth * dpr;
  const height = canvas.height = canvas.clientHeight * dpr;
  ctx.clearRect(0, 0, width, height);

  const padding = 28 * dpr;
  const maxY = Math.max(1, ...points.map(p => Number(p.count || 0)));

  const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#22d3ee';
  const grid = getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#334155';
  const muted = getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim() || '#64748b';

  // grid
  ctx.strokeStyle = grid;
  ctx.lineWidth = 1 * dpr;
  for (let i = 0; i <= 4; i++) {
    const y = padding + (height - padding * 2) * (i / 4);
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();
  }

  const n = Math.max(1, points.length);
  const stepX = (width - padding * 2) / Math.max(1, n - 1);

  ctx.strokeStyle = accent;
  ctx.lineWidth = 2 * dpr;
  ctx.beginPath();
  points.forEach((p, i) => {
    const x = padding + i * stepX;
    const y = height - padding - (height - padding * 2) * (Number(p.count || 0) / maxY);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // labels (every ~3 points)
  ctx.fillStyle = muted;
  ctx.font = `${12 * dpr}px sans-serif`;
  ctx.textAlign = 'center';
  const every = Math.max(1, Math.floor(n / 5));
  points.forEach((p, i) => {
    if (i % every !== 0 && i !== n - 1) return;
    const x = padding + i * stepX;
    const label = (p.day || '').toString().slice(5); // MM-DD
    ctx.fillText(label, x, height - padding + 14 * dpr);
  });
}
