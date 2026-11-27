const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      "X-Content-Type-Options": "nosniff",
      ...CORS_HEADERS,
    },
  });
}

const TE = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sha256Hex(pwd) {
  return toHex(await crypto.subtle.digest("SHA-256", TE.encode(pwd)));
}

async function hashPassword(pwd) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 100000;
  const key = await crypto.subtle.importKey("raw", TE.encode(pwd), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256
  );
  return `pbkdf2$${iterations}$${toHex(salt)}$${toHex(bits)}`;
}

async function verifyPassword(pwd, stored) {
  if (typeof stored !== "string") return { ok: false, needUpgrade: false };
  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    if (parts.length !== 4) return { ok: false, needUpgrade: false };
    const iterations = Number(parts[1]);
    const salt = new Uint8Array(parts[2].match(/../g).map((h) => parseInt(h, 16)));
    const key = await crypto.subtle.importKey("raw", TE.encode(pwd), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256
    );
    return { ok: toHex(bits) === parts[3], needUpgrade: false };
  }
  return { ok: (await sha256Hex(pwd)) === stored, needUpgrade: true };
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const db = env.DB;

  if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

  try {
    if (!db) return json({ ok: false, error: "数据库未绑定：请在 Pages 设置 → 函数 → D1 数据库绑定中添加变量 DB" }, 500);

    const getUser = async (req) => {
      const auth = req.headers.get("Authorization");
      if (!auth || !auth.startsWith("Bearer ")) return null;
      const token = auth.slice(7).trim();
      if (!token) return null;
      try {
        const row = await db.prepare("SELECT id, token_expire FROM users WHERE token=?").bind(token).first();
        if (!row) return null;
        if (row.token_expire != null && row.token_expire < Date.now()) return null;
        return row.id;
      } catch (e) {
        const row = await db.prepare("SELECT id FROM users WHERE token=?").bind(token).first();
        return row ? row.id : null;
      }
    };

    const setToken = async (userId, token) => {
      const expire = Date.now() + 30 * 24 * 60 * 60 * 1000;
      try {
        await db.prepare("UPDATE users SET token=?, token_expire=? WHERE id=?").bind(token, expire, userId).run();
      } catch (e) {
        await db.prepare("UPDATE users SET token=? WHERE id=?").bind(token, userId).run();
      }
    };

    const clearToken = async (userId) => {
      try {
        await db.prepare("UPDATE users SET token=NULL, token_expire=NULL WHERE id=?").bind(userId).run();
      } catch (e) {
        await db.prepare("UPDATE users SET token=NULL WHERE id=?").bind(userId).run();
      }
    };

    if (path === "/api/register" && method === "POST") {
      const b = await request.json();
      const username = (b.username || "").trim();
      const password = b.password || "";
      if (!username || !password) return json({ ok: false, error: "用户名和密码必填" }, 400);
      if (username.length < 2 || username.length > 32) return json({ ok: false, error: "用户名长度 2-32 位" }, 400);
      if (password.length < 6 || password.length > 128) return json({ ok: false, error: "密码长度 6-128 位" }, 400);
      try {
        await db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
          .bind(username, await hashPassword(password)).run();
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: "用户名已存在" }, 400);
      }
    }

    if (path === "/api/login" && method === "POST") {
      const b = await request.json();
      const username = (b.username || "").trim();
      const password = b.password || "";
      const row = await db.prepare("SELECT id, password FROM users WHERE username=?").bind(username).first();
      if (!row) return json({ ok: false, error: "用户名或密码错误" }, 401);
      const { ok, needUpgrade } = await verifyPassword(password, row.password);
      if (!ok) return json({ ok: false, error: "用户名或密码错误" }, 401);
      if (needUpgrade) {
        await db.prepare("UPDATE users SET password=? WHERE id=?")
          .bind(await hashPassword(password), row.id).run();
      }
      const token = crypto.randomUUID();
      await setToken(row.id, token);
      return json({ ok: true, token });
    }

    if (path === "/api/logout" && method === "POST") {
      const userId = await getUser(request);
      if (userId) await clearToken(userId);
      return json({ ok: true });
    }

    if (path === "/api/me" && method === "GET") {
      const userId = await getUser(request);
      if (!userId) return json({ ok: false, error: "未登录或登录已失效" }, 401);
      const row = await db.prepare("SELECT id, username FROM users WHERE id=?").bind(userId).first();
      return json(row);
    }

    if (path === "/api/password" && method === "POST") {
      const userId = await getUser(request);
      if (!userId) return json({ ok: false, error: "未登录或登录已失效" }, 401);
      const b = await request.json();
      const oldPwd = b.old_password || "";
      const newPwd = b.new_password || "";
      if (newPwd.length < 6 || newPwd.length > 128) return json({ ok: false, error: "新密码长度 6-128 位" }, 400);
      const row = await db.prepare("SELECT password FROM users WHERE id=?").bind(userId).first();
      const { ok } = await verifyPassword(oldPwd, row.password);
      if (!ok) return json({ ok: false, error: "原密码错误" }, 400);
      await db.prepare("UPDATE users SET password=? WHERE id=?")
        .bind(await hashPassword(newPwd), userId).run();
      await clearToken(userId);
      return json({ ok: true, message: "密码已修改，请重新登录" });
    }

    if (path === "/api/get_cfg" && method === "GET") {
      const sn = url.searchParams.get("sn");
      if (!sn) return json({ error: "sn required" }, 400);
      const row = await db.prepare(
        "SELECT c.url, c.model FROM device d JOIN config c ON d.config_id = c.id WHERE d.sn=?"
      ).bind(sn).first();
      if (!row) return json({ error: "not found" }, 404);
      return json({ url: row.url, model: row.model });
    }

    const userId = await getUser(request);
    if (!userId) return json({ ok: false, error: "未登录或登录已失效" }, 401);

    if (path === "/api/config" && method === "GET") {
      const { results } = await db.prepare(
        "SELECT id, name, url, key, model FROM config WHERE user_id=? ORDER BY id DESC"
      ).bind(userId).all();
      return json(results);
    }

    if (path === "/api/config" && method === "POST") {
      const b = await request.json();
      const name = (b.name || "").trim();
      const apiUrl = (b.url || "").trim();
      const model = (b.model || "").trim();
      if (!name || !apiUrl || !model) return json({ ok: false, error: "名字、地址、模型不能为空" }, 400);
      try { new URL(apiUrl); } catch (e) { return json({ ok: false, error: "接口地址格式不正确" }, 400); }
      if (b.id) {
        const info = await db.prepare(
          "UPDATE config SET name=?, url=?, key=?, model=? WHERE id=? AND user_id=?"
        ).bind(name, apiUrl, b.key || "", model, b.id, userId).run();
        if (info.changes === 0) return json({ ok: false, error: "配置不存在" }, 404);
      } else {
        await db.prepare(
          "INSERT INTO config (user_id, name, url, key, model) VALUES (?,?,?,?,?)"
        ).bind(userId, name, apiUrl, b.key || "", model).run();
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
      const { results } = await db.prepare(
        "SELECT d.sn, d.remark, d.config_id, c.name AS config_name FROM device d LEFT JOIN config c ON d.config_id = c.id WHERE d.user_id=? ORDER BY d.sn"
      ).bind(userId).all();
      return json(results);
    }

    if (path === "/api/device" && method === "POST") {
      const b = await request.json();
      const sn = (b.sn || "").trim();
      if (!sn) return json({ ok: false, error: "SN 必填" }, 400);
      if (sn.length > 64) return json({ ok: false, error: "SN 过长" }, 400);
      const exist = await db.prepare("SELECT user_id FROM device WHERE sn=?").bind(sn).first();
      if (exist && exist.user_id !== userId) return json({ ok: false, error: "该 SN 已被其他用户绑定" }, 403);
      const configId = b.config_id || null;
      if (configId) {
        const cfg = await db.prepare("SELECT id FROM config WHERE id=? AND user_id=?").bind(configId, userId).first();
        if (!cfg) return json({ ok: false, error: "绑定的 API 配置不存在" }, 400);
      }
      await db.prepare(
        "INSERT INTO device (sn, user_id, remark, config_id) VALUES (?,?,?,?) ON CONFLICT(sn) DO UPDATE SET remark=excluded.remark, config_id=excluded.config_id"
      ).bind(sn, userId, b.remark || "", configId).run();
      return json({ ok: true });
    }

    if (path === "/api/device" && method === "DELETE") {
      const sn = url.searchParams.get("sn");
      await db.prepare("DELETE FROM device WHERE sn=? AND user_id=?").bind(sn, userId).run();
      return json({ ok: true });
    }

    return json({ error: "Not Found" }, 404);
  } catch (e) {
    return json({ ok: false, error: "服务器内部错误" }, 500);
  }
}
