// functions/exam/[[path]].js  ->  served at  /exam  and  /exam/*
//
// Pretty exam URLs:
//   /exam/84            -> take exam 84
//   /exam/84/practice   -> practice mode for exam 84
//
// The page itself is the static file exam.html. This function only checks the URL, then serves that
// file under the pretty URL (same technique as Clipt's [code].js). Old links such as
// /exam.html?...  are redirected (301) to the new form, so nothing that was shared breaks.

const NUM = /^\d{1,12}$/;
const SLUG = /^[A-Za-z0-9_-]{4,64}$/;
const SEC = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Robots-Tag': 'noindex, nofollow',
};

function go(url, path, status) {
  return new Response(null, { status: status || 302, headers: { Location: new URL(path, url).toString(), ...SEC } });
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const p = url.pathname.split('/').filter(Boolean);          // e.g. ['exam', ...]
  const q = url.searchParams;
  // legacy:  /exam?id=84&practice=1  ->  /exam/84/practice
  if (p.length === 1 && NUM.test(q.get('id') || '')) return go(url, '/exam/' + q.get('id') + (q.get('practice') === '1' ? '/practice' : ''), 301);
  // valid:  /exam/84   /exam/84/practice
  const ok = NUM.test(p[1] || '') && (p.length === 2 || (p.length === 3 && p[2] === 'practice'));
  if (!ok) return go(url, '/dashboard');
  const r = await env.ASSETS.fetch(new URL('/exam', url));  // clean URL of exam.html (never ask for .html: Pages redirects it)
  const out = new Response(r.body, r);
  for (const [k, v] of Object.entries(SEC)) out.headers.set(k, v);
  return out;
}
