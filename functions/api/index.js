export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const db = env.DB;

  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization" }
  });

  if (method === "OPTIONS") return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization" } });

  const hashPassword = async (pwd) => {
    const msgUint8 = new TextEncoder().encode(pwd);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const getUser = async (req) => {
    const auth = req.headers.get("Authorization");
    if (!auth || !auth.startsWith("Bearer ")) return null;
    const token = auth.split(" ")[1];
    const row = await db.prepare("SELECT id FROM users WHERE token=?").bind(token).first();
    return row ? row.id : null;
  };

  try {
    if (path === "/api/register" && method === "POST") {
      const b = await request.json();
      if (!b.username || !b.password) return json({ ok: false, error: "用户名和密码必填" }, 400);
      const hashed = await hashPassword(b.password);
      try {
        await db.prepare("INSERT INTO users (username, password) VALUES (?, ?)").bind(b.username, hashed).run();
        return json({ ok: true });
      } catch (e) { return json({ ok: false, error: "用户名已存在" }, 400); }
    }

    if (path === "/api/login" && method === "POST") {
      const b = await request.json();
      const hashed = await hashPassword(b.password || "");
      const user = await db.prepare("SELECT id FROM users WHERE username=? AND password=?").bind(b.username, hashed).first();
      if (!user) return json({ ok: false, error: "用户名或密码错误" }, 401);
      
      const token = crypto.randomUUID();
      await db.prepare("UPDATE users SET token=? WHERE id=?").bind(token, user.id).run();
      return json({ ok: true, token });
    }

    if (path === "/api/logout" && method === "POST") {
      const userId = await getUser(request);
      if (userId) await db.prepare("UPDATE users SET token=NULL WHERE id=?").bind(userId).run();
      return json({ ok: true });
    }

    const userId = await getUser(request);
    if (path !== "/api/get_cfg" && !userId) return json({ ok: false, error: "未登录或登录已失效" }, 401);

    if (path === "/api/config" && method === "GET") {
      const { results } = await db.prepare("SELECT id, name, url, key, model FROM config WHERE user_id=? ORDER BY id DESC").bind(userId).all();
      return json(results);
    }

    if (path === "/api/config" && method === "POST") {
      const b = await request.json();
      if (!b.name || !b.url || !b.model) return json({ ok: false, error: "参数不全" }, 400);
      if (b.id) {
        await db.prepare("UPDATE config SET name=?, url=?, key=?, model=? WHERE id=? AND user_id=?").bind(b.name, b.url, b.key || "", b.model, b.id, userId).run();
      } else {
        await db.prepare("INSERT INTO config (user_id, name, url, key, model) VALUES (?,?,?,?,?)").bind(userId, b.name, b.url, b.key || "", b.model).run();
      }
      return json({ ok: true });
    }

    if (path === "/api/config" && method === "DELETE") {
      const id = url.searchParams.get("id");
      await db.prepare("UPDATE device SET config_id=NULL WHERE config_id=? AND user_id=?").bind(id, userId).run();
      await db.prepare("DELETE FROM config WHERE id=? AND user_id=?").bind(id, userId).run();
      return json({ ok: true });
    }

    if (path === "/api/device" && method === "GET") {
      const { results } = await db.prepare(`SELECT d.sn, d.remark, d.config_id, c.name AS config_name FROM device d LEFT JOIN config c ON d.config_id = c.id WHERE d.user_id=? ORDER BY d.sn`).bind(userId).all();
      return json(results);
    }

    if (path === "/api/device" && method === "POST") {
      const b = await request.json();
      if (!b.sn) return json({ ok: false, error: "sn 必填" }, 400);
      await db.prepare(`INSERT INTO device (sn, user_id, remark, config_id) VALUES (?,?,?,?) ON CONFLICT(sn) DO UPDATE SET remark=excluded.remark, config_id=excluded.config_id`).bind(b.sn, userId, b.remark || "", b.config_id || null).run();
      return json({ ok: true });
    }

    if (path === "/api/device" && method === "DELETE") {
      const sn = url.searchParams.get("sn");
      await db.prepare("DELETE FROM device WHERE sn=? AND user_id=?").bind(sn, userId).run();
      return json({ ok: true });
    }

    if (path === "/api/get_cfg" && method === "GET") {
      const sn = url.searchParams.get("sn");
      const row = await db.prepare(`SELECT c.url, c.model FROM device d JOIN config c ON d.config_id = c.id WHERE d.sn=?`).bind(sn).first();
      if (!row) return json({ error: "not found" }, 404);
      return json({ url: row.url, model: row.model });
    }

    return json({ error: "Not Found" }, 404);
  } catch (e) {
    return json({ ok: false, error: String(e) }, 500);
  }
}