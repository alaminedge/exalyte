// functions/dl.js  ->  served at  /dl
//
// Streams a *public* Google Drive file through your own domain so the saved file gets the name you want:
//   /dl?id=FILE_ID                      -> keeps the original Drive file name
//   /dl?id=FILE_ID&fn=My%20Notes        -> saves as "My Notes.pdf" (extension is added if missing)
//   /dl?id=FILE_ID&meta=1               -> JSON { ok, name, size, type } (used by download.html)
//   /dl?ping=1                          -> JSON { ok: true }               (lets the page know this function exists)
//
// A browser ignores the HTML `download="name"` attribute for files that live on another website, so the
// only way to control the saved name is to send the file from your own domain with a Content-Disposition
// header. That is all this function does. Nothing is stored, and only drive.usercontent.google.com is contacted.

const ID_RE = /^[A-Za-z0-9_-]{10,}$/;
const MAX_NAME = 150;
const MAX_BYTES = 1024 * 1024 * 1024;       // refuse files above ~1 GB so this can't be used as a free big-file proxy
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

const KNOWN_EXT = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'json', 'zip', 'rar', '7z', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'mp3', 'wav', 'mp4', 'mkv', 'avi', 'mov', 'webm', 'apk', 'epub', 'html', 'htm'];
const TYPE_EXT = {
  'application/pdf': '.pdf', 'application/zip': '.zip', 'application/vnd.android.package-archive': '.apk',
  'application/msword': '.doc', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
  'application/vnd.ms-excel': '.xls', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
  'application/vnd.ms-powerpoint': '.ppt', 'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
  'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif', 'image/webp': '.webp',
  'audio/mpeg': '.mp3', 'video/mp4': '.mp4', 'text/plain': '.txt', 'text/csv': '.csv'
};

function json(obj, status, extra) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {})
  });
}

// Name Google sent with the file (handles both filename*=UTF-8''… and filename="…")
function originalName(cd) {
  if (!cd) return '';
  let m = cd.match(/filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i);
  if (m) { try { return decodeURIComponent(m[2].trim().replace(/^"|"$/g, '')); } catch (e) { /* fall through */ } }
  m = cd.match(/filename\s*=\s*"((?:[^"\\]|\\.)*)"/i) || cd.match(/filename\s*=\s*([^;]+)/i);
  return m ? m[1].trim() : '';
}

// A safe file name: no folders, no control characters, no characters Android/Windows reject
function cleanName(n) {
  return String(n == null ? '' : n)
    .replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '')
    .replace(/[\\/:*?"<>|]+/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/^[\s.]+/, '')
    .slice(0, MAX_NAME)
    .trim();
}

function extOf(name) { const m = /\.([A-Za-z0-9]{1,8})$/.exec(name || ''); return m ? m[1].toLowerCase() : ''; }

// custom name + original name/type -> final saved name (keeps the real extension so the file still opens)
function finalName(custom, original, contentType) {
  const c = cleanName(custom), o = cleanName(original);
  if (!c) return o || '';
  const origExt = extOf(o) || (TYPE_EXT[String(contentType || '').split(';')[0].trim().toLowerCase()] || '').slice(1);
  const cExt = extOf(c);
  if (cExt && (cExt === origExt || KNOWN_EXT.indexOf(cExt) !== -1)) return c;   // they already typed an extension
  return origExt ? c + '.' + origExt : c;
}

function rfc5987(s) { return encodeURIComponent(s).replace(/['()*]/g, function (ch) { return '%' + ch.charCodeAt(0).toString(16).toUpperCase(); }); }
function dispositionFor(name) {
  const ext = extOf(name);
  let ascii = name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\%]/g, '_');
  if (!/[A-Za-z0-9]/.test(ascii.replace(/\.[A-Za-z0-9]{1,8}$/, ''))) ascii = 'download' + (ext ? '.' + ext : '');   // e.g. an all-Bengali name
  return 'attachment; filename="' + ascii + '"; filename*=UTF-8\'\'' + rfc5987(name);
}

async function whyNotAFile(up) {
  if (up.status === 429) return 'quota';
  let text = '';
  try { text = (await up.text()).slice(0, 6000); } catch (e) { /* ignore */ }
  if (/quota|too many users|download limit/i.test(text)) return 'quota';
  if (up.status === 401 || up.status === 403 || /sign in|accounts\.google\.com|request access|you need access|permission/i.test(text)) return 'no_access';
  if (up.status === 404) return 'not_found';
  return 'unavailable';
}

export async function onRequest(context) {
  const request = context.request;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, HEAD' } });
  }
  const url = new URL(request.url);
  if (url.searchParams.get('ping') === '1') return json({ ok: true });

  const id = url.searchParams.get('id') || '';
  if (!ID_RE.test(id)) return json({ error: 'bad_id' }, 400);
  const wantMeta = url.searchParams.get('meta') === '1';

  const headers = new Headers({ 'User-Agent': UA, Accept: '*/*' });
  const range = request.headers.get('Range');
  if (wantMeta) headers.set('Range', 'bytes=0-0');
  else if (range && /^bytes=\d*-\d*(,\d*-\d*)*$/.test(range)) headers.set('Range', range);

  let up;
  try {
    up = await fetch('https://drive.usercontent.google.com/download?id=' + encodeURIComponent(id) + '&export=download&confirm=t', { headers: headers, redirect: 'follow' });
  } catch (e) {
    return wantMeta ? json({ error: 'unavailable' }, 502) : errorPage('Couldn\u2019t reach Google Drive. Please try again in a moment.', 502);
  }

  const cd = up.headers.get('Content-Disposition') || '';
  const type = up.headers.get('Content-Type') || 'application/octet-stream';
  const isFile = (up.status === 200 || up.status === 206) && (cd !== '' || !/text\/html/i.test(type));
  if (!isFile) {
    const why = await whyNotAFile(up);
    if (wantMeta) return json({ error: why }, why === 'no_access' ? 403 : why === 'not_found' ? 404 : 502);
    const msgs = {
      no_access: 'This file isn\u2019t shared publicly. Ask the sender to set it to \u201cAnyone with the link\u201d in Google Drive.',
      not_found: 'This file could not be found. It may have been deleted or the link is wrong.',
      quota: 'Google is limiting downloads for this file right now. Please try again later.',
      unavailable: 'Google Drive did not return the file. Please try again later.'
    };
    return errorPage(msgs[why] || msgs.unavailable, why === 'no_access' ? 403 : why === 'not_found' ? 404 : 502);
  }

  const orig = originalName(cd);
  const cr = up.headers.get('Content-Range') || '';
  const total = Number((/\/(\d+)$/.exec(cr) || [])[1]) || (up.status === 200 ? Number(up.headers.get('Content-Length')) || 0 : 0);

  if (wantMeta) {
    try { if (up.body) await up.body.cancel(); } catch (e) { /* ignore */ }
    return json({ ok: true, name: orig, size: total || null, type: type.split(';')[0] });
  }
  if (total > MAX_BYTES) {
    try { if (up.body) await up.body.cancel(); } catch (e) { /* ignore */ }
    return errorPage('This file is too large to download through this page.', 413);
  }

  const custom = url.searchParams.get('fn') || '';
  const name = custom ? finalName(custom, orig, type) : '';
  const out = new Headers();
  out.set('Content-Type', type);
  out.set('Content-Disposition', name ? dispositionFor(name) : (cd || dispositionFor(orig || 'download')));   // no rename -> Google's own header, untouched
  ['Content-Length', 'Content-Range', 'Accept-Ranges', 'Last-Modified'].forEach(function (h) { const v = up.headers.get(h); if (v) out.set(h, v); });
  out.set('Cache-Control', 'private, no-store');
  out.set('X-Content-Type-Options', 'nosniff');
  out.set('Referrer-Policy', 'no-referrer');

  if (request.method === 'HEAD') {
    try { if (up.body) await up.body.cancel(); } catch (e) { /* ignore */ }
    return new Response(null, { status: up.status, headers: out });
  }
  return new Response(up.body, { status: up.status, headers: out });
}

function errorPage(message, status) {
  const esc = String(message).replace(/[&<>]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]; });
  const html = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Download unavailable</title>' +
    '<style>body{font-family:system-ui,sans-serif;background:#f8f9fa;color:#202124;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px}' +
    '.c{background:#fff;border:1px solid #dadce0;border-radius:12px;padding:28px;max-width:420px;text-align:center}h1{font-size:1.2rem;margin:0 0 8px}p{color:#5f6368;line-height:1.6;margin:0 0 18px}' +
    'a{display:inline-block;background:#1a73e8;color:#fff;text-decoration:none;padding:12px 22px;border-radius:4px}</style></head><body><div class="c"><h1>Download unavailable</h1><p>' + esc + '</p><a href="/">Back to site</a></div></body></html>';
  return new Response(html, { status: status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}
