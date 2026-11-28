const UPSTREAM = 'https://xiaozhi.me';

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const target = UPSTREAM + url.pathname + url.search;

  const headers = new Headers();
  const ct = request.headers.get('Content-Type');
  if (ct) headers.set('Content-Type', ct);
  const auth = request.headers.get('Authorization');
  if (auth) headers.set('Authorization', auth);
  const cookie = request.headers.get('Cookie');
  if (cookie) headers.set('Cookie', cookie);
  headers.set('Accept', request.headers.get('Accept') || 'application/json');
  headers.set('User-Agent', request.headers.get('User-Agent') || 'Mozilla/5.0');

  const init = { method: request.method, headers, redirect: 'manual' };
  if (!['GET', 'HEAD'].includes(request.method)) {
    init.body = await request.arrayBuffer();
  }

  try {
    const resp = await fetch(target, init);
    const out = new Headers();
    const ctype = resp.headers.get('Content-Type') || '';
    if (ctype) out.set('Content-Type', ctype);
    out.set('Cache-Control', 'no-store');
    try {
      if (typeof resp.headers.getSetCookie === 'function') {
        for (const v of resp.headers.getSetCookie()) out.append('Set-Cookie', v);
      } else {
        const c = resp.headers.get('set-cookie');
        if (c) out.append('Set-Cookie', c);
      }
    } catch (e) {}
    return new Response(await resp.arrayBuffer(), { status: resp.status, headers: out });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, message: '代理失败: ' + String(e) }), {
      status: 502,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  }
}
