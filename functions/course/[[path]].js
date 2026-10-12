// functions/course/[[path]].js  ->  served at  /course  and  /course/*
//
// Pretty course URL (the link you share):
//   /course/<batch-slug>   -> course details page  ->  "Enroll"  ->  /payment/<batch-slug>
//
// The page itself is the static file course.html. This function (same technique as Clipt's [code].js):
//   1. checks the URL shape,
//   2. looks the batch up once (cached ~60 s per isolate) so WhatsApp / Telegram / Facebook link previews
//      show the course name, price and picture (crawlers do not run the page's JavaScript),
//   3. serves course.html under the pretty URL with those preview tags filled in.
// Unknown or non-public batches get a 404 status (the page then shows "no longer available").

const SLUG = /^[A-Za-z0-9_-]{4,64}$/;
const SEC = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};
const G = globalThis;
const TTL = 60 * 1000;

function go(url, path, status) {
  return new Response(null, { status: status || 302, headers: { Location: new URL(path, url).toString(), ...SEC } });
}

async function findBatch(env, slug) {
  const M = G.__courseCache || (G.__courseCache = new Map());
  const hit = M.get(slug);
  if (hit && hit.exp > Date.now()) return hit.v;
  let v = null;
  try {
    const row = await env.DB.prepare(
      'SELECT name, description, image_url, fee, is_public, total_exams FROM batches WHERE public_slug = ?'
    ).bind(slug).first();
    if (row && row.is_public) v = row;
  } catch (e) { return undefined; }            // DB problem: serve the plain page, never fail the request
  if (M.size > 500) M.clear();
  M.set(slug, { v, exp: Date.now() + TTL });
  return v;
}

function plain(html) {
  return String(html || '')
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;|&#160;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
    .replace(/\s+/g, ' ').trim();
}
function clip(s, n) { return s.length > n ? s.slice(0, n - 1).trimEnd() + '\u2026' : s; }
function feeText(fee) { const n = Number(fee); return isFinite(n) && n > 0 ? '\u09f3' + n.toLocaleString('en-US') : 'Free'; }
function absImage(src, origin) {
  const s = String(src || '').trim();
  if (!s) return origin + '/images/exalyte.png';
  try { const u = new URL(s, origin); return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : origin + '/images/exalyte.png'; }
  catch (e) { return origin + '/images/exalyte.png'; }
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const p = url.pathname.split('/').filter(Boolean);
  if (!(p.length === 2 && SLUG.test(p[1]))) return go(url, '/batches');   // /course, /course/x/y, bad slug

  const slug = p[1];
  const batch = await findBatch(env, slug);
  const r = await env.ASSETS.fetch(new URL('/course', url));              // clean URL of course.html (never ask for .html)
  const headers = new Headers(r.headers);
  for (const [k, v] of Object.entries(SEC)) headers.set(k, v);

  if (batch === undefined) return new Response(r.body, { status: r.status, headers });   // DB hiccup -> plain page
  if (batch === null) {                                                                  // not found / not public
    headers.set('X-Robots-Tag', 'noindex, nofollow');
    return new Response(r.body, { status: 404, headers });
  }

  const title = clip(batch.name || 'Course', 80) + ' \u2014 Exalyte';
  const bits = [feeText(batch.fee)];
  if (Number(batch.total_exams) > 0) bits.push(batch.total_exams + (Number(batch.total_exams) === 1 ? ' exam' : ' exams'));
  const text = plain(batch.description);
  const desc = clip(bits.join(' \u00b7 ') + (text ? ' \u2014 ' + text : ' \u2014 Enroll in this batch on Exalyte.'), 200);
  const image = absImage(batch.image_url, url.origin);
  const canonical = url.origin + '/course/' + slug;

  const setContent = (v) => ({ element(e) { e.setAttribute('content', v); } });
  const rewritten = new HTMLRewriter()
    .on('title', { element(e) { e.setInnerContent(title); } })
    .on('meta[name="description"]', setContent(desc))
    .on('meta[property="og:title"]', setContent(title))
    .on('meta[property="og:description"]', setContent(desc))
    .on('meta[property="og:image"]', setContent(image))
    .on('meta[property="og:url"]', setContent(canonical))
    .on('meta[name="twitter:title"]', setContent(title))
    .on('meta[name="twitter:description"]', setContent(desc))
    .on('meta[name="twitter:image"]', setContent(image))
    .on('link[rel="canonical"]', { element(e) { e.setAttribute('href', canonical); } })
    .transform(new Response(r.body, { status: r.status, headers }));
  return rewritten;
}
