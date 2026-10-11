// functions/result/[[path]].js  ->  served at  /result  and  /result/*
//
// Pretty result URLs:
//   /result/84/12   -> result of attempt 12 on exam 84
//   /result/84      -> latest result of exam 84
//
// The page itself is the static file result.html. This function only checks the URL, then serves that
// file under the pretty URL (same technique as Clipt's [code].js). Old links such as
// /result.html?...  are redirected (301) to the new form, so nothing that was shared breaks.

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
  const p = url.pathname.split('/').filter(Boolean);          // e.g. ['result', ...]
  const q = url.searchParams;
  // legacy:  /result?examId=84&attemptId=12  ->  /result/84/12
  if (p.length === 1 && NUM.test(q.get('examId') || '')) return go(url, '/result/' + q.get('examId') + (NUM.test(q.get('attemptId') || '') ? '/' + q.get('attemptId') : ''), 301);
  // valid:  /result/84   /result/84/12   (exam id, optional attempt id)
  const ok = NUM.test(p[1] || '') && (p.length === 2 || (p.length === 3 && NUM.test(p[2])));
  if (!ok) return go(url, '/dashboard');
  const r = await env.ASSETS.fetch(new URL('/result', url));  // clean URL of result.html (never ask for .html: Pages redirects it)
  const out = new Response(r.body, r);
  for (const [k, v] of Object.entries(SEC)) out.headers.set(k, v);
  return out;
}
