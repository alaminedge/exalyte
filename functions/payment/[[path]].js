// functions/payment/[[path]].js  ->  served at  /payment  and  /payment/*
//
// Pretty enrol URLs:
//   /payment/<batch-slug>   -> enrol in a batch
//
// The page itself is the static file payment.html. This function only checks the URL, then serves that
// file under the pretty URL (same technique as Clipt's [code].js). Old links such as
// /payment.html?...  are redirected (301) to the new form, so nothing that was shared breaks.

const NUM = /^\d{1,12}$/;
const SLUG = /^[A-Za-z0-9_-]{4,64}$/;
const SEC = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

function go(url, path, status) {
  return new Response(null, { status: status || 302, headers: { Location: new URL(path, url).toString(), ...SEC } });
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const p = url.pathname.split('/').filter(Boolean);          // e.g. ['payment', ...]
  const q = url.searchParams;
  // legacy:  /payment?batch=<slug>  ->  /payment/<slug>
  if (p.length === 1 && SLUG.test(q.get('batch') || '')) return go(url, '/payment/' + q.get('batch'), 301);
  // valid:  /payment/<batch-slug>
  const ok = p.length === 2 && SLUG.test(p[1]);
  if (!ok) return go(url, '/batches');
  const r = await env.ASSETS.fetch(new URL('/payment', url));  // clean URL of payment.html (never ask for .html: Pages redirects it)
  const out = new Response(r.body, r);
  for (const [k, v] of Object.entries(SEC)) out.headers.set(k, v);
  return out;
}
