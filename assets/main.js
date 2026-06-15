// ═══════════════════════════════════════════════════
// Exalyte — main.js
// Shared utilities for all pages
// ═══════════════════════════════════════════════════

const API = '/api';

// ── Auth helpers ──────────────────────────────────────
function getToken() { return localStorage.getItem('exalyte_token'); }
function getUser()  { return JSON.parse(localStorage.getItem('exalyte_user') || 'null'); }

function requireAuth() {
  const t = getToken(), u = getUser();
  if (!t || !u) { window.location.href = 'index.html'; return false; }
  return true;
}
function requireAdmin() {
  const t = getToken(), u = getUser();
  if (!t || !u || !u.is_admin) { window.location.href = 'index.html'; return false; }
  return true;
}

function logout() {
  localStorage.removeItem('exalyte_token');
  localStorage.removeItem('exalyte_user');
  window.location.href = 'index.html';
}

// ── API fetch wrapper ─────────────────────────────────
async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(options.headers || {}) };
  const res = await fetch(API + path, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

// ── HTML escape ──
function esc(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Theme ──
const THEME_KEY = 'exalyte_theme';
function getSystemTheme() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function applyTheme(theme) {
  const resolved = theme === 'system' ? getSystemTheme() : theme;
  document.documentElement.setAttribute('data-theme', resolved);
  document.querySelectorAll('.theme-toggle').forEach(btn => {
    btn.innerHTML = resolved === 'dark' ? '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>' : '<svg viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>';
  });
}
function toggleTheme() {
  const stored = localStorage.getItem(THEME_KEY) || 'system';
  const current = stored === 'system' ? getSystemTheme() : stored;
  const next = current === 'dark' ? 'light' : 'dark';
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
}
function initTheme() {
  const stored = localStorage.getItem(THEME_KEY) || 'system';
  applyTheme(stored);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if ((localStorage.getItem(THEME_KEY) || 'system') === 'system') applyTheme('system');
  });
}

// ── Notification toast ──
function notify(msg, isError = false) {
  let el = document.getElementById('_notif');
  if (!el) {
    el = document.createElement('div');
    el.id = '_notif';
    el.className = 'notif';
    el.innerHTML = `<svg viewBox="0 0 24 24" id="_notifIcon"></svg><span id="_notifMsg"></span>`;
    document.body.appendChild(el);
  }
  el.classList.toggle('error', isError);
  document.getElementById('_notifMsg').textContent = msg;
  const icon = document.getElementById('_notifIcon');
  icon.innerHTML = isError
    ? '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'
    : '<polyline points="20 6 9 17 4 12"/>';
  el.classList.add('show');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove('show'), 3500);
}

// ── Modal helpers ──
function openModal(id) {
  document.getElementById(id)?.classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeModal(id) {
  document.getElementById(id)?.classList.remove('open');
  document.body.style.overflow = '';
}

// ── Button loading state ──
function setLoading(btnId, loading) {
  const btn = typeof btnId === 'string' ? document.getElementById(btnId) : btnId;
  if (!btn) return;
  btn.classList.toggle('loading', loading);
  btn.disabled = loading;
}

// ── Format helpers ──
function formatTime(seconds) {
  if (seconds <= 0) return 'Ended';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${String(m).padStart(2,'0')}:${String(seconds % 60).padStart(2,'0')}`;
}
function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}
function gradeInfo(perc) {
  if (perc >= 90) return { label: 'Outstanding', color: '#22c55e', glow: 'rgba(34,197,94,.15)' };
  if (perc >= 80) return { label: 'Excellent', color: '#22c55e', glow: 'rgba(34,197,94,.1)' };
  if (perc >= 60) return { label: 'Good', color: '#a855f7', glow: 'rgba(168,85,247,.1)' };
  if (perc >= 40) return { label: 'Needs Work', color: '#f59e0b', glow: 'rgba(245,158,11,.1)' };
  return { label: 'Keep Trying', color: '#ef4444', glow: 'rgba(239,68,68,.1)' };
}

// ── Mobile sidebar ──
function initMobileSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  const hamburger = document.getElementById('hamburger');
  if (!sidebar) return;
  function openSidebar() { sidebar.classList.add('open'); overlay?.classList.add('open'); document.body.style.overflow = 'hidden'; }
  function closeSidebar() { sidebar.classList.remove('open'); overlay?.classList.remove('open'); document.body.style.overflow = ''; }
  hamburger?.addEventListener('click', openSidebar);
  overlay?.addEventListener('click', closeSidebar);
  if (window.innerWidth <= 768) {
    sidebar.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', closeSidebar);
    });
  }
}

// ── Sticky Header ──
function initStickyHeader() {
  const header = document.querySelector('.sticky-header');
  if (!header) return;
  window.addEventListener('scroll', () => {
    header.classList.toggle('scrolled', window.scrollY > 50);
  });
}

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initMobileSidebar();
  initStickyHeader();
});
