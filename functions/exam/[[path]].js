// functions/exam/[[path]].js  ->  served at  /exam  and  /exam/*
//
// Pretty exam URLs:
//   /exam/k7m3xq            -> take the exam with public code k7m3xq
//   /exam/k7m3xq/practice   -> practice mode
//
// The page itself is the static file exam.html. This function checks the URL and serves that file under
// the pretty URL. OLD links keep working:
//   * numeric ids from before the change  (/exam/84 ...)  -> 301 to the exam's 6-character code, but only for
//     exams that existed at the time of the switch (exams created later can never be reached by number);
//   * query-string links  (/exam?...)  -> 301 to the new form.
// Codes are lowercase letters + digits, always contain a letter, and never change once assigned.

const NUM = /^\d{1,12}$/;
const CODE = /^[A-Za-z0-9]{6}$/;
const isCode = (s) => CODE.test(s) && /[A-Za-z]/.test(s);
const SEC = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Robots-Tag': 'noindex, nofollow',
};

function go(url, path, status) {
  return new Response(null, { status: status || 302, headers: { Location: new URL(path, url).toString(), ...SEC } });
}

// numeric id or code  ->  lowercase code, or null
async function codeFor(env, raw) {
  const s = String(raw || '');
  if (isCode(s)) return s.toLowerCase();
  if (!NUM.test(s)) return null;
  try {
    const row = await env.DB.prepare(
      "SELECT public_id FROM exams WHERE id = ? AND id <= (SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'legacy_exam_id_max')"
    ).bind(s).first();
    return (row && row.public_id) || null;
  } catch (e) { return null; }
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const p = url.pathname.split('/').filter(Boolean);        // ['exam', ...]
  const q = url.searchParams;
  // /exam?id=84&practice=1  or  /exam?id=k7m3xq   (old query links)
  if (p.length === 1) {
    const c = await codeFor(env, q.get('id'));
    return c ? go(url, '/exam/' + c + (q.get('practice') === '1' ? '/practice' : ''), 301) : go(url, '/dashboard');
  }
  // valid:  /exam/<code>   /exam/<code>/practice      (also accepts an old numeric id and redirects)
  const ok = p.length === 2 || (p.length === 3 && p[2] === 'practice');
  if (!ok) return go(url, '/dashboard');
  const code = await codeFor(env, p[1]);
  if (!code) return go(url, '/dashboard');
  if (p[1] !== code) return go(url, '/exam/' + code + (p[2] ? '/practice' : ''), 301);   // numeric / UPPERCASE -> canonical
  const r = await env.ASSETS.fetch(new URL('/exam', url));   // clean URL of exam.html (never ask for .html: Pages redirects it)
  const out = new Response(r.body, r);
  for (const [k, v] of Object.entries(SEC)) out.headers.set(k, v);
  return out;
}
