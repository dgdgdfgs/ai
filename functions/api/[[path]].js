const UPSTREAM = 'https://xiaozhi.me/api';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const target = UPSTREAM + url.pathname.replace(/^\/api/, '') + url.search;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  const headers = new Headers();
  const ct = request.headers.get('Content-Type');
  if (ct) headers.set('Content-Type', ct);
  const auth = request.headers.get('Authorization');
  if (auth) headers.set('Authorization', auth);
  headers.set('Accept', 'application/json');

  const init = { method: request.method, headers };
  if (!['GET', 'HEAD'].includes(request.method)) {
    init.body = await request.arrayBuffer();
  }

  try {
    const resp = await fetch(target, init);
    const body = await resp.arrayBuffer();
    const outHeaders = new Headers();
    const ctype = resp.headers.get('Content-Type');
    if (ctype) outHeaders.set('Content-Type', ctype);
    Object.keys(CORS).forEach(k => outHeaders.set(k, CORS[k]));
    return new Response(body, { status: resp.status, headers: outHeaders });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, message: '代理请求失败: ' + String(e) }), {
      status: 502,
      headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
    });
  }
}
