// functions/api/index.js — Cloudflare Pages Functions + D1
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const db = env.DB;

  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }

  try {
    // ===== API 配置 =====
    if (path === "/api/config" && method === "GET") {
      const { results } = await db
        .prepare("SELECT id, name, url, key, model FROM config ORDER BY id DESC")
        .all();
      return json(results);
    }

    if (path === "/api/config" && method === "POST") {
      const b = await request.json();
      if (!b.name || !b.url || !b.model) return json({ ok: false, error: "name/url/model 必填" }, 400);
      if (b.id) {
        await db.prepare("UPDATE config SET name=?, url=?, key=?, model=? WHERE id=?")
          .bind(b.name, b.url, b.key || "", b.model, b.id).run();
      } else {
        await db.prepare("INSERT INTO config (name, url, key, model) VALUES (?,?,?,?)")
          .bind(b.name, b.url, b.key || "", b.model).run();
      }
      return json({ ok: true });
    }

    if (path === "/api/config" && method === "DELETE") {
      const id = url.searchParams.get("id");
      if (!id) return json({ ok: false, error: "缺少 id" }, 400);
      await db.prepare("UPDATE device SET config_id=NULL WHERE config_id=?").bind(id).run();
      await db.prepare("DELETE FROM config WHERE id=?").bind(id).run();
      return json({ ok: true });
    }

    // ===== 设备绑定 =====
    if (path === "/api/device" && method === "GET") {
      const { results } = await db.prepare(
        `SELECT d.sn, d.remark, d.config_id, c.name AS config_name
         FROM device d LEFT JOIN config c ON d.config_id = c.id
         ORDER BY d.sn`
      ).all();
      return json(results);
    }

    if (path === "/api/device" && method === "POST") {
      const b = await request.json();
      if (!b.sn) return json({ ok: false, error: "sn 必填" }, 400);
      await db.prepare(
        `INSERT INTO device (sn, remark, config_id) VALUES (?,?,?)
         ON CONFLICT(sn) DO UPDATE SET remark=excluded.remark, config_id=excluded.config_id`
      ).bind(b.sn, b.remark || "", b.config_id || null).run();
      return json({ ok: true });
    }

    if (path === "/api/device" && method === "DELETE") {
      const sn = url.searchParams.get("sn");
      if (!sn) return json({ ok: false, error: "缺少 sn" }, 400);
      await db.prepare("DELETE FROM device WHERE sn=?").bind(sn).run();
      return json({ ok: true });
    }

    // ===== ESP32 专用 =====
    if (path === "/api/get_cfg" && method === "GET") {
      const sn = url.searchParams.get("sn");
      if (!sn) return json({ error: "缺少 sn" }, 400);
      const row = await db.prepare(
        `SELECT c.url, c.model FROM device d
         JOIN config c ON d.config_id = c.id WHERE d.sn = ?`
      ).bind(sn).first();
      if (!row) return json({ error: "not found" }, 404);
      return json({ url: row.url, model: row.model });
    }

    return json({ error: "Not Found", path, method }, 404);
  } catch (e) {
    return json({ ok: false, error: String(e) }, 500);
  }
}