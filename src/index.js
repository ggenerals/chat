import seedFile from "./users.json";

const SEED_USERS = (typeof seedFile === "string" ? JSON.parse(seedFile) : seedFile).users;
const enc = new TextEncoder();
const TOKEN_TTL = 24 * 3600 * 1000;

// ================= 加密工具 =================
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hmacKey(env) {
  const secret = env.JWT_SECRET;
  if (!secret) throw new Error("未配置 JWT_SECRET");
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
function b64urlEncode(bytes) {
  let bin = ""; for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (str.length % 4)) % 4);
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
async function signToken(env, payload) {
  const body = b64urlEncode(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(body));
  return body + "." + b64urlEncode(new Uint8Array(sig));
}
async function verifyToken(env, token) {
  try {
    const [body, sig] = String(token || "").split(".");
    if (!body || !sig) return null;
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(env), b64urlDecode(sig), enc.encode(body));
    if (!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8" } });

// ================= Worker 入口 =================
export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname === "/") {
      return new Response(CHAT_HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    const stub = env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName("main"));
    return stub.fetch(request);
  },
};

// ================= Durable Object =================
export class ChatRoom {
  constructor(state, env) { this.state = state; this.env = env; }

  async ensureSeeded() {
    if (await this.state.storage.get("meta:seeded")) return;
    const has = await this.state.storage.list({ prefix: "user:", limit: 1 });
    if (has.size === 0) {
      const puts = {};
      for (const u of SEED_USERS) {
        puts["user:" + u.username] = { 
          username: u.username, 
          passwordHash: u.passwordHash, 
          role: u.role === "admin" ? "admin" : "user", 
          pwv: 1,
          perms: { cmd: false, notice: false, mute: false, ai: true },
          muted: false
        };
      }
      await this.state.storage.put(puts);
    }
    await this.state.storage.put("meta:seeded", Date.now());
  }

  async getUserRec(username) { 
    const rec = await this.state.storage.get("user:" + username);
    if (rec && !rec.perms) {
      rec.perms = { cmd: false, notice: false, mute: false, ai: true };
      rec.muted = false;
    }
    return rec; 
  }
  
  async hasPerm(username, perm) {
    const rec = await this.getUserRec(username);
    if (!rec) return false;
    if (rec.role === "admin") return true;
    return !!(rec.perms && rec.perms[perm]);
  }

  bearer(request) { const h = request.headers.get("Authorization") || ""; return h.startsWith("Bearer ") ? h.slice(7) : null; }

  async getNotice() { return (await this.state.storage.get("meta:notice")) || ""; }
  async setNotice(text) { const t = String(text || "").slice(0, 2000); await this.state.storage.put("meta:notice", t); return t; }
  async getAIPrompt() { 
    return (await this.state.storage.get("meta:ai_prompt")) || "你是一只乖巧的猫娘。你正在一个多人聊天群中，请根据最近的聊天记录上下文，用简短、接地气的中文聊天。回答30-50字。支持使用 Markdown 和 LaTeX 公式（用 $ 和 $$ 包裹）。"; 
  }
  async setAIPrompt(text) { const t = String(text || "").slice(0, 2000); await this.state.storage.put("meta:ai_prompt", t); return t; }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/ws") return this.handleWebSocket(request, url);

    if (url.pathname === "/api/login" && request.method === "POST") {
      await this.ensureSeeded();
      let username, password;
      try { ({ username, password } = await request.json()); } catch { return json({ error: "请求格式错误" }, 400); }
      const rec = await this.getUserRec(username);
      const hash = await sha256Hex(String(password || ""));
      if (!rec || rec.passwordHash !== hash) return json({ error: "用户名或密码错误" }, 401);
      try {
        const token = await signToken(this.env, { u: rec.username, r: rec.role, v: rec.pwv, exp: Date.now() + TOKEN_TTL });
        return json({ token, username: rec.username, role: rec.role });
      } catch { return json({ error: "服务器未配置 JWT_SECRET" }, 500); }
    }

    if (url.pathname === "/api/me") {
      const token = this.bearer(request) || url.searchParams.get("token");
      const payload = await verifyToken(this.env, token);
      if (!payload) return json({ error: "未登录或已过期" }, 401);
      const rec = await this.getUserRec(payload.u);
      if (!rec || rec.pwv !== payload.v) return json({ error: "登录已失效" }, 401);
      return json({ username: rec.username, role: rec.role });
    }

    if (url.pathname === "/api/change-password" && request.method === "POST") return this.handleChangePassword(request);

    if (url.pathname === "/api/notice") {
      if (request.method === "GET") return json({ text: await this.getNotice() });
      if (request.method === "POST") {
        const payload = await verifyToken(this.env, this.bearer(request));
        if (!payload) return json({ error: "未登录" }, 401);
        if (!(await this.hasPerm(payload.u, "notice"))) return json({ error: "无权限编辑公告" }, 403);
        let text; try { ({ text } = await request.json()); } catch { return json({ error: "格式错误" }, 400); }
        const savedText = await this.setNotice(text);
        this.broadcast({ type: "notice", text: savedText });
        return json({ ok: true, text: savedText });
      }
    }

    if (url.pathname === "/api/prompt") {
      if (request.method === "GET") return json({ text: await this.getAIPrompt() });
      if (request.method === "POST") {
        const payload = await verifyToken(this.env, this.bearer(request));
        if (!payload || payload.r !== "admin") return json({ error: "仅超管可修改 AI 提示词" }, 403);
        let text; try { ({ text } = await request.json()); } catch { return json({ error: "格式错误" }, 400); }
        const savedText = await this.setAIPrompt(text);
        return json({ ok: true, text: savedText });
      }
    }

    // ---------- 用户管理 API (仅超管可用) ----------
    if (url.pathname === "/api/users" && request.method === "GET") {
      const payload = await verifyToken(this.env, this.bearer(request) || url.searchParams.get("token"));
      if (!payload) return json({ error: "未登录" }, 401);
      const rec = await this.getUserRec(payload.u);
      if (!rec || rec.pwv !== payload.v || rec.role !== "admin") return json({ error: "无超管权限" }, 403);

      const allUsers = await this.state.storage.list({ prefix: "user:" });
      const list = [];
      for (const [_, val] of allUsers) {
        if (!val.perms) val.perms = { cmd: false, notice: false, mute: false, ai: true };
        if (val.muted === undefined) val.muted = false;
        list.push({ username: val.username, role: val.role, perms: val.perms, muted: val.muted });
      }
      return json({ users: list });
    }

    if (url.pathname === "/api/manage" && request.method === "POST") {
      const payload = await verifyToken(this.env, this.bearer(request));
      if (!payload) return json({ error: "未登录" }, 401);
      const rec = await this.getUserRec(payload.u);
      if (!rec || rec.pwv !== payload.v || rec.role !== "admin") return json({ error: "无超管权限" }, 403);

      let body; try { body = await request.json(); } catch { return json({ error: "格式错误" }, 400); }
      const targetRec = await this.getUserRec(body.username);
      if (!targetRec) return json({ error: "用户不存在" }, 404);
      
      if (targetRec.role === "admin" && body.username !== payload.u) {
         return json({ error: "不能修改其他超管" }, 403);
      }

      if (body.action === "set_perms") {
        targetRec.perms = { ...targetRec.perms, ...body.perms };
        await this.state.storage.put("user:" + body.username, targetRec);
        return json({ ok: true });
      }
      
      if (body.action === "toggle_mute") {
        if (targetRec.role === "admin") return json({ error: "不能禁言超管" }, 403);
        // 【新增】无法对拥有禁言权的管理员禁言
        if (targetRec.perms && targetRec.perms.mute) return json({ error: "不能禁言拥有禁言权的管理员" }, 403);
        
        targetRec.muted = !targetRec.muted;
        await this.state.storage.put("user:" + body.username, targetRec);
        this.broadcast({ type: "system", text: targetRec.muted ? "🔇 " + payload.u + " 禁言了 " + body.username : "🔊 " + payload.u + " 解除了 " + body.username + " 的禁言" });
        return json({ ok: true, muted: targetRec.muted });
      }
      
      if (body.action === "delete") {
        if (body.username === payload.u) return json({ error: "不能删除自己" }, 400);
        if (targetRec.role === "admin") return json({ error: "不能删除超管" }, 403);
        await this.state.storage.delete("user:" + body.username);
        for (const session of this.state.getWebSockets()) {
          if (this.getUser(session) === body.username) {
            try { session.send(JSON.stringify({ type: "kicked", reason: "账号已被管理员删除" })); } catch {}
            try { session.close(4001, "deleted"); } catch {}
          }
        }
        this.broadcast({ type: "system", text: "🗑️ " + payload.u + " 删除了用户 " + body.username });
        return json({ ok: true });
      }
      
      if (body.action === "resetpw") {
        const newPwd = body.password;
        if (!newPwd || newPwd.length < 6) return json({ error: "密码至少6位" }, 400);
        targetRec.passwordHash = await sha256Hex(newPwd);
        targetRec.pwv = (targetRec.pwv || 1) + 1;
        await this.state.storage.put("user:" + body.username, targetRec);
        return json({ ok: true });
      }
      
      return json({ error: "未知操作" }, 400);
    }

    return json({ error: "Not Found" }, 404);
  }

  async handleChangePassword(request) {
    const payload = await verifyToken(this.env, this.bearer(request));
    if (!payload) return json({ error: "未登录或已过期" }, 401);
    let oldPassword, newPassword;
    try { ({ oldPassword, newPassword } = await request.json()); } catch { return json({ error: "请求格式错误" }, 400); }
    const rec = await this.getUserRec(payload.u);
    if (!rec || rec.pwv !== payload.v) return json({ error: "登录已失效" }, 401);
    if (rec.passwordHash !== await sha256Hex(String(oldPassword || ""))) return json({ error: "当前密码错误" }, 403);
    const newPwd = String(newPassword || "");
    if (newPwd.length < 6 || newPwd.length > 64) return json({ error: "新密码长度需为 6~64 位" }, 400);
    rec.passwordHash = await sha256Hex(newPwd); rec.pwv = (rec.pwv || 1) + 1;
    await this.state.storage.put("user:" + rec.username, rec);
    const token = await signToken(this.env, { u: rec.username, r: rec.role, v: rec.pwv, exp: Date.now() + TOKEN_TTL });
    return json({ ok: true, token });
  }

  async handleWebSocket(request, url) {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected WebSocket upgrade", { status: 426 });
    await this.ensureSeeded();
    const payload = await verifyToken(this.env, url.searchParams.get("token"));
    if (!payload) return new Response("Unauthorized", { status: 401 });
    const rec = await this.getUserRec(payload.u);
    if (!rec || rec.pwv !== payload.v) return new Response("Unauthorized", { status: 401 });

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.state.acceptWebSocket(server, ["u:" + rec.username, "r:" + rec.role]);

    server.send(JSON.stringify({ type: "history", messages: await this.getHistory(50) }));
    const notice = await this.getNotice();
    if (notice) server.send(JSON.stringify({ type: "notice", text: notice }));
    this.broadcast({ type: "system", text: rec.username + " 加入了聊天室" });
    this.broadcast({ type: "online", users: this.getOnlineUsers() });
    return new Response(null, { status: 101, webSocket: client });
  }

  getUser(ws) { const t = this.state.getTags(ws).find(t => t.startsWith("u:")); return t ? t.slice(2) : null; }
  getOnlineUsers() { const set = new Set(); for (const ws of this.state.getWebSockets()) { const u = this.getUser(ws); if (u) set.add(u); } return [...set]; }
  broadcast(obj) { const payload = JSON.stringify(obj); for (const session of this.state.getWebSockets()) { try { session.send(payload); } catch {} } }

  // 【核心修改】调整消息处理顺序：指令优先于禁言检查
  async webSocketMessage(ws, raw) {
    const sender = this.getUser(ws);
    let text;
    try { text = String(JSON.parse(raw).text || "").slice(0, 2000); } catch { return; }
    if (!text || !sender) return;

    const rec = await this.getUserRec(sender);
    const isMuted = rec && rec.muted;

    // 1. 提取 AI 提示词
    let aiPrompt = null;
    if (text.startsWith("/ai ")) aiPrompt = text.slice(4).trim();
    else if (text.includes("@bot")) aiPrompt = text.replace(/@bot/g, "").trim();

    // 2. 拦截斜杠命令（指令与一般发言分开，禁言状态下仍可执行有权限的指令）
    if (text.startsWith("/") && !text.startsWith("/ai ")) {
      await this.handleCommand(ws, sender, text);
      return;
    }

    // 3. 检查是否被禁言（只拦截普通消息和 AI 提问）
    if (isMuted) {
      ws.send(JSON.stringify({ type: "system", text: "🚫 你已被禁言，无法发送消息或使用 AI。" }));
      return;
    }

    // 4. 检查 AI 权限
    if (aiPrompt && !(await this.hasPerm(sender, "ai"))) {
      ws.send(JSON.stringify({ type: "system", text: "🚫 你没有使用 AI 的权限。" }));
      return;
    }

    // 5. 作为普通消息广播并保存
    const record = {
      type: "message", user: sender,
      role: rec.role === "admin" ? "admin" : "user", text, time: Date.now(),
    };
    this.broadcast(record);
    const key = "msg:" + String(record.time).padStart(15, "0") + ":" + crypto.randomUUID();
    await this.state.storage.put(key, record);

    // 6. 触发 AI
    if (aiPrompt) await this.handleAIRequest(aiPrompt, sender);
  }

  async webSocketClose(ws, code) {
    if (code === 4001) return;
    const user = this.getUser(ws);
    if (user) {
      this.broadcast({ type: "system", text: user + " 离开了聊天室" });
      this.broadcast({ type: "online", users: this.getOnlineUsers() });
    }
  }
  async webSocketError() {}

  async handleCommand(ws, sender, text) {
    const parts = text.trim().split(/\s+/);
    const cmd = parts[0];
    const say = (t) => ws.send(JSON.stringify({ type: "system", text: t }));
    const HELP = `📖 可用命令列表：
━━━━━━━━━━━━━━━━━━━━
【常规与 AI】
/help : 显示本帮助信息
/ai [问题] 或 @bot [问题] : 召唤 AI 助手 (需 AI 权限)

【聊天管理】(需指令权)
/online : 查看当前在线用户列表
/clear : 清空当前聊天记录
/kick [用户名] : 将指定用户踢出房间

【用户管理】(需指令权)
/adduser [用户名] [密码] : 创建新用户
/deluser [用户名] : 彻底删除用户并踢出
/resetpw [用户名] [新密码] : 重置指定用户的密码

【公告与禁言】
/notice [公告内容] : 更新顶栏公告 (需公告权)
/mute [用户名] : 禁言指定用户 (需禁言权)
/unmute [用户名] : 解除用户禁言 (需禁言权)

【超管专属】
/prompt [系统提示词] : 修改 AI 的人设与规则`;

    if (cmd === "/help") return say(HELP);

    // --- 公告权限 ---
    if (cmd === "/notice") {
      if (!(await this.hasPerm(sender, "notice"))) return say("🚫 无权限编辑公告");
      const text = parts.slice(1).join(" "); 
      const savedText = await this.setNotice(text);
      this.broadcast({ type: "notice", text: savedText }); 
      return say("✅ 公告已更新");
    }

    // --- 禁言权限 ---
    if (cmd === "/mute") {
      if (!(await this.hasPerm(sender, "mute"))) return say("🚫 无权限禁言他人");
      if (!parts[1]) return say("用法：/mute <用户名>");
      const target = parts[1]; 
      const tRec = await this.getUserRec(target);
      if (!tRec) return say("用户不存在"); 
      if (tRec.role === "admin") return say("⚠️ 不能禁言超管");
      // 【新增】无法对拥有禁言权的管理员禁言
      if (tRec.perms && tRec.perms.mute) return say("⚠️ 不能禁言拥有禁言权的管理员");
      
      tRec.muted = true; 
      await this.state.storage.put("user:" + target, tRec);
      return this.broadcast({ type: "system", text: "🔇 " + sender + " 禁言了 " + target });
    }
    
    if (cmd === "/unmute") {
      if (!(await this.hasPerm(sender, "mute"))) return say("🚫 无权限解除禁言");
      if (!parts[1]) return say("用法：/unmute <用户名>");
      const target = parts[1]; 
      const tRec = await this.getUserRec(target);
      if (!tRec) return say("用户不存在");
      tRec.muted = false; 
      await this.state.storage.put("user:" + target, tRec);
      return this.broadcast({ type: "system", text: "🔊 " + sender + " 解除了 " + target + " 的禁言" });
    }

    // --- 基础管理指令权限 (cmd) ---
    const cmdPerms = ["/kick", "/clear", "/adduser", "/deluser", "/resetpw", "/online"];
    if (cmdPerms.includes(cmd)) {
      if (!(await this.hasPerm(sender, "cmd"))) return say("🚫 无权限执行此管理指令");
      
      if (cmd === "/kick") {
        if (!parts[1]) return say("用法：/kick <用户名>");
        const target = parts[1]; let kicked = 0;
        for (const session of this.state.getWebSockets()) {
          if (this.getUser(session) === target) {
            try { session.send(JSON.stringify({ type: "kicked", reason: "你已被管理员踢出" })); } catch {}
            try { session.close(4001, "kicked"); } catch {} kicked++;
          }
        }
        this.broadcast({ type: "system", text: kicked ? "🔨 " + sender + " 将 " + target + " 踢出了聊天室" : "用户 " + target + " 不在线" });
        this.broadcast({ type: "online", users: this.getOnlineUsers() }); 
        return;
      }
      
      if (cmd === "/clear") {
        const stored = await this.state.storage.list({ prefix: "msg:" });
        if (stored.size) await this.state.storage.delete([...stored.keys()]);
        this.broadcast({ type: "clear" }); 
        this.broadcast({ type: "system", text: "🧹 " + sender + " 清空了聊天记录" });
        return;
      }
      
      if (cmd === "/online") {
        const users = this.getOnlineUsers();
        ws.send(JSON.stringify({ 
          type: "system", 
          text: "👥 当前在线 (" + users.length + " 人):\n" + users.join(", ") 
        }));
        return ws.send(JSON.stringify({ type: "online", users: users }));
      }
      
      if (cmd === "/adduser") {
        if (parts.length < 3) return say("用法：/adduser <用户名> <密码>"); 
        const username = parts[1], password = parts.slice(2).join(" ");
        if (!/^[A-Za-z0-9_\u4e00-\u9fa5]{1,20}$/.test(username)) return say("用户名限中英文/数字/下划线，1~20字符");
        if (password.length < 6) return say("密码至少6位");
        if (await this.getUserRec(username)) return say("用户已存在");
        await this.state.storage.put("user:" + username, { username, passwordHash: await sha256Hex(password), role: "user", pwv: 1, perms: { cmd: false, notice: false, mute: false, ai: true }, muted: false });
        return say("✅ 已创建用户 " + username);
      }
      
      if (cmd === "/deluser") {
        if (!parts[1]) return say("用法：/deluser <用户名>");
        const target = parts[1]; 
        if (target === sender) return say("⚠️ 不能删除自己");
        const tRec = await this.getUserRec(target);
        if (!tRec) return say("用户不存在"); 
        if (tRec.role === "admin") return say("⚠️ 不能删除超管");
        await this.state.storage.delete("user:" + target);
        for (const session of this.state.getWebSockets()) {
          if (this.getUser(session) === target) {
            try { session.send(JSON.stringify({ type: "kicked", reason: "账号已被删除" })); } catch {}
            try { session.close(4001, "deleted"); } catch {}
          }
        }
        this.broadcast({ type: "system", text: "🗑️ " + sender + " 删除了用户 " + target });
        this.broadcast({ type: "online", users: this.getOnlineUsers().filter(u => u !== target) }); 
        return;
      }
      
      if (cmd === "/resetpw") {
        if (parts.length < 3) return say("用法：/resetpw <用户名> <新密码>");
        const target = parts[1], newPwd = parts.slice(2).join(" ");
        const tRec = await this.getUserRec(target);
        if (!tRec) return say("用户不存在"); 
        if (tRec.role === "admin") return say("⚠️ 不能重置超管密码");
        if (newPwd.length < 6) return say("新密码至少6位");
        tRec.passwordHash = await sha256Hex(newPwd); 
        tRec.pwv = (tRec.pwv || 1) + 1;
        await this.state.storage.put("user:" + target, tRec); 
        return say("✅ 已重置 " + target + " 的密码");
      }
    }

    // --- 超管专属命令 ---
    if (cmd === "/prompt") {
      const rec = await this.getUserRec(sender);
      if (rec.role !== "admin") return say("🚫 仅超管可修改 AI 提示词");
      const text = parts.slice(1).join(" "); 
      await this.setAIPrompt(text); 
      return say("✅ AI 提示词已更新");
    }

    say("未知命令。" + HELP);
  }

  async getHistory(limit) {
    const rows = await this.state.storage.list({ prefix: "msg:", reverse: true, limit });
    return [...rows.values()].reverse();
  }

  async handleAIRequest(prompt, sender) {
    this.broadcast({ type: "system", text: "🤖 AI-Bot 正在思考..." });
    const sysPrompt = await this.getAIPrompt();
    const history = await this.getHistory(15); 
    const messages = [{ role: "system", content: sysPrompt }];
    for (const msg of history) {
      let cleanText = msg.text;
      if (cleanText.startsWith("/ai ")) cleanText = cleanText.slice(4);
      cleanText = cleanText.replace(/@bot/g, "").trim();
      messages.push({ role: msg.role === "bot" ? "assistant" : "user", content: msg.role === "bot" ? cleanText : msg.user + ": " + cleanText });
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    try {
      if (!this.env.AI_API_URL || !this.env.AI_API_KEY) throw new Error("未配置 AI_API_URL 或 AI_API_KEY");
      const response = await fetch(this.env.AI_API_URL, {
        method: "POST", signal: controller.signal,
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + this.env.AI_API_KEY },
        body: JSON.stringify({ model: this.env.AI_MODEL || "gpt-4o-mini", messages: messages, stream: false }),
      });
      if (!response.ok) throw new Error("API 返回 " + response.status);
      const data = await response.json();
      const aiText = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || "抱歉，我没有得到有效的回复。";
      const record = { type: "message", user: "AI-Bot", role: "bot", text: aiText, time: Date.now() };
      this.broadcast(record);
      const key = "msg:" + String(record.time).padStart(15, "0") + ":ai-" + crypto.randomUUID();
      await this.state.storage.put(key, record);
    } catch (err) {
      const reason = err.name === "AbortError" ? "请求超时（30秒）" : err.message;
      this.broadcast({ type: "system", text: "❌ AI-Bot 调用失败: " + reason });
    } finally { clearTimeout(timeout); }
  }
}

// ================= 前端页面 =================
const CHAT_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>聊天室</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css">
<script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.8/dist/purify.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #15161c; color: #e8e8ea; display: flex; justify-content: center; height: 100vh; }
  .overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.55); align-items: center; justify-content: center; z-index: 10; }
  .box { background: #23242e; padding: 28px; border-radius: 14px; width: 330px; display: flex; flex-direction: column; gap: 12px; }
  .box.wide { width: 800px; max-width: 95%; max-height: 90vh; overflow-y: auto; }
  .box h2 { font-size: 18px; text-align: center; margin-bottom: 6px; }
  .box input, .box textarea { padding: 10px 12px; border: none; border-radius: 8px; background: #15161c; color: #eee; outline: none; font-family: inherit; }
  .box textarea { resize: vertical; min-height: 120px; font-family: monospace; font-size: 13px; }
  .box button { padding: 10px; border: none; border-radius: 8px; background: #4f46e5; color: #fff; cursor: pointer; }
  .box .ghost { background: #3a3b47; }
  .box .row { display: flex; gap: 8px; }
  .box .row button { flex: 1; }
  .err { color: #f87171; font-size: 13px; min-height: 16px; }
  #app { width: 100%; max-width: 800px; display: none; flex-direction: column; }
  header { padding: 12px 16px; background: #23242e; display: flex; align-items: center; gap: 10px; font-weight: 600; flex-wrap: wrap; }
  #dot { width: 10px; height: 10px; border-radius: 50%; background: #f59e0b; }
  #dot.on { background: #22c55e; }
  #me { margin-left: auto; font-size: 13px; font-weight: 400; opacity: .8; }
  .hbtn { background: none; border: 1px solid #555; color: #aaa; border-radius: 6px; padding: 3px 10px; cursor: pointer; font-size: 12px; margin-left: 4px; }
  
  #notice-container { display: none; padding: 12px 16px; background: #2d2e3a; border-bottom: 1px solid #3a3b47; max-height: 300px; overflow-y: auto; }
  #notice-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  #notice-title { color: #f59e0b; font-weight: 600; font-size: 14px; }
  #notice-content { font-size: 14px; line-height: 1.6; color: #d1d5db; }
  
  #online { padding: 6px 16px; font-size: 12px; opacity: .65; background: #1c1d26; }
  #messages { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 10px; }
  
  .msg { background: #23242e; padding: 10px 14px; border-radius: 10px; max-width: 85%; word-break: break-word; }
  .msg.mine { align-self: flex-end; background: #4f46e5; }
  .msg .meta { font-size: 12px; opacity: .6; margin-bottom: 4px; }
  .sys { 
    align-self: center; font-size: 12px; opacity: .8; white-space: pre-wrap; text-align: left;
    background: #1c1d26; padding: 10px 14px; border-radius: 8px; max-width: 90%; font-family: monospace;
  }
  
  .msg.bot { 
    align-self: center; background: linear-gradient(135deg, #2563eb, #3b82f6); color: white; 
    max-width: 90%; border-radius: 12px; box-shadow: 0 4px 12px rgba(59,130,246,0.3); padding: 12px 16px; 
  }
  .msg.bot .meta { color: rgba(255,255,255,0.9); font-weight: 500; }
  .msg.bot .msg-body code { background: rgba(255,255,255,0.2); color: #fff; padding: 2px 4px; border-radius: 4px; }
  .msg.bot .msg-body pre { background: rgba(0,0,0,0.3); padding: 8px; border-radius: 6px; overflow-x: auto; }
  .msg.bot .msg-body pre code { background: none; padding: 0; }
  .msg.bot .msg-body a { color: #bfdbfe; text-decoration: underline; }
  .msg.bot .msg-body blockquote { border-left: 3px solid rgba(255,255,255,0.5); padding-left: 8px; opacity: 0.9; }

  form { display: flex; gap: 8px; padding: 12px 16px; background: #23242e; }
  #input { flex: 1; padding: 10px 14px; border: none; border-radius: 8px; background: #15161c; color: #eee; outline: none; font-size: 15px; }
  button.send { padding: 10px 20px; border: none; border-radius: 8px; background: #4f46e5; color: #fff; font-size: 15px; cursor: pointer; }

  .msg-body h1, .msg-body h2, .msg-body h3 { margin: 8px 0 4px; font-size: 1.1em; font-weight: 600; }
  .msg-body p { margin: 4px 0; }
  .msg-body code { background: rgba(255,255,255,0.1); padding: 2px 4px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }
  .msg-body pre { background: #111; padding: 8px; border-radius: 6px; overflow-x: auto; margin: 6px 0; }
  .msg-body pre code { background: none; padding: 0; }
  .msg-body ul, .msg-body ol { padding-left: 20px; margin: 4px 0; }
  .msg-body blockquote { border-left: 3px solid #555; padding-left: 8px; opacity: 0.8; margin: 4px 0; }
  .msg-body a { color: #60a5fa; text-decoration: underline; }

  #notice-content h1, #notice-content h2, #notice-content h3 { font-size: 1.1em; margin: 6px 0; font-weight: 600; }
  #notice-content p { margin: 4px 0; }
  #notice-content code { background: rgba(255,255,255,0.1); padding: 2px 4px; border-radius: 4px; font-family: monospace; }
  #notice-content pre { background: #111; padding: 8px; border-radius: 6px; overflow-x: auto; margin: 6px 0; }

  .user-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .user-table th, .user-table td { padding: 8px; text-align: left; border-bottom: 1px solid #333; }
  .user-table th { background: #1c1d26; color: #aaa; font-weight: 500; }
  .switch { position: relative; display: inline-block; width: 34px; height: 20px; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #444; transition: .4s; border-radius: 20px; }
  .slider:before { position: absolute; content: ""; height: 14px; width: 14px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%; }
  input:checked + .slider { background-color: #4f46e5; }
  input:checked + .slider:before { transform: translateX(14px); }
  input:disabled + .slider { background-color: #222; cursor: not-allowed; opacity: 0.5; }
  .act-btn { padding: 4px 8px; font-size: 11px; border: none; border-radius: 4px; cursor: pointer; margin-right: 4px; color: #fff; }
  .act-btn.mute { background: #d97706; }
  .act-btn.reset { background: #2563eb; }
  .act-btn.del { background: #dc2626; }
  .act-btn:disabled { background: #444; cursor: not-allowed; opacity: 0.5; }
</style>
</head>
<body>

<div class="overlay" id="login">
  <form class="box" id="login-form">
    <h2>🔐 登录聊天室</h2>
    <input id="lu" placeholder="账号" autocomplete="username" />
    <input id="lp" type="password" placeholder="密码" autocomplete="current-password" />
    <div class="err" id="login-err"></div>
    <button type="submit">登 录</button>
  </form>
</div>

<div class="overlay" id="pwd-modal">
  <form class="box" id="pwd-form">
    <h2>🔑 修改密码</h2>
    <input id="pw-old" type="password" placeholder="当前密码" />
    <input id="pw-new" type="password" placeholder="新密码（至少 6 位）" />
    <input id="pw-new2" type="password" placeholder="再次输入新密码" />
    <div class="err" id="pwd-msg"></div>
    <div class="row">
      <button type="button" class="ghost" id="pwd-cancel">取消</button>
      <button type="submit">确认修改</button>
    </div>
  </form>
</div>

<div class="overlay" id="notice-modal">
  <form class="box" id="notice-form" style="width: 500px; max-width: 90%;">
    <h2>📢 编辑公告</h2>
    <textarea id="notice-input" placeholder="支持 Markdown 和 LaTeX ($...$, $$...$$)"></textarea>
    <div class="err" id="notice-msg"></div>
    <div class="row">
      <button type="button" class="ghost" id="notice-cancel">取消</button>
      <button type="submit">发布</button>
    </div>
  </form>
</div>

<div class="overlay" id="prompt-modal">
  <form class="box" id="prompt-form" style="width: 500px; max-width: 90%;">
    <h2>🤖 编辑 AI 提示词</h2>
    <textarea id="prompt-input" placeholder="定义 AI 的人设、语气和规则..."></textarea>
    <div class="err" id="prompt-msg"></div>
    <div class="row">
      <button type="button" class="ghost" id="prompt-cancel">取消</button>
      <button type="submit">保存</button>
    </div>
  </form>
</div>

<div class="overlay" id="user-modal">
  <div class="box wide">
    <h2>👥 用户与权限管理</h2>
    <div style="overflow-x: auto;">
      <table class="user-table">
        <thead>
          <tr>
            <th>用户</th><th>角色</th>
            <th>指令</th><th>公告</th><th>禁言权</th><th>AI</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="user-tbody"></tbody>
      </table>
    </div>
    <div class="err" id="user-msg" style="margin-top: 10px;"></div>
    <div class="row" style="margin-top: 16px;">
      <button type="button" class="ghost" id="user-cancel">关闭</button>
    </div>
  </div>
</div>

<div id="app">
  <header>
    <span id="dot"></span>
    <span>💬 聊天室</span>
    <span id="me"></span>
    <button class="hbtn" id="edit-notice-btn" style="display: none;">公告</button>
    <button class="hbtn" id="edit-prompt-btn" style="display: none;">AI 提示词</button>
    <button class="hbtn" id="manage-users-btn" style="display: none;">用户管理</button>
    <button class="hbtn" id="pwd-btn">改密</button>
    <button class="hbtn" id="logout">退出</button>
  </header>
  
  <div id="notice-container">
    <div id="notice-header"><span id="notice-title">📢 公告与注意事项</span></div>
    <div id="notice-content"></div>
  </div>

  <div id="online">在线: -</div>
  <div id="messages"></div>
  <form id="form">
    <input id="input" placeholder="输入消息 (/ai 提问 或 @bot 提问)，回车发送…" autocomplete="off" />
    <button class="send" type="submit">发送</button>
  </form>
</div>

<script>
(function () {
  var user = "", role = "", token = "", ws = null, currentNoticeText = "";

  var loginEl = document.getElementById("login");
  var pwdModal = document.getElementById("pwd-modal");
  var noticeModal = document.getElementById("notice-modal");
  var promptModal = document.getElementById("prompt-modal");
  var userModal = document.getElementById("user-modal");
  var appEl = document.getElementById("app");
  var messagesEl = document.getElementById("messages");
  var onlineEl = document.getElementById("online");
  var dotEl = document.getElementById("dot");
  var inputEl = document.getElementById("input");
  var noticeContainer = document.getElementById("notice-container");
  var noticeContent = document.getElementById("notice-content");

  function renderContent(text) {
    if (!text) return "";
    const mathBlocks = [];
    let processedText = String(text).replace(/\\$\\$([\\s\\S]+?)\\$\\$|\\$([^\\$\\n]+?)\\$/g, function(match, p1, p2) {
      const isDisplay = !!p1; const latex = isDisplay ? p1 : p2;
      try {
        const html = katex.renderToString(latex, { displayMode: isDisplay, throwOnError: false });
        const placeholder = \`@@MATH\${mathBlocks.length}@@\`; mathBlocks.push(html); return placeholder;
      } catch (e) { return match; }
    });
    marked.setOptions({ breaks: true, gfm: true });
    let html = marked.parse(processedText);
    const clean = DOMPurify.sanitize(html, { ALLOWED_ATTR: ['href', 'target', 'src', 'alt', 'class', 'style', 'width', 'height'] });
    return clean.replace(/@@MATH(\\d+)@@/g, function(match, index) { return mathBlocks[parseInt(index)]; });
  }

  function showLogin() { loginEl.style.display = "flex"; pwdModal.style.display = "none"; noticeModal.style.display = "none"; promptModal.style.display = "none"; userModal.style.display = "none"; appEl.style.display = "none"; }
  function logout() { localStorage.removeItem("do-chat-token"); if (ws) { try { ws.close(); } catch (e) {} } location.reload(); }
  document.getElementById("logout").onclick = logout;

  document.getElementById("login-form").onsubmit = function (e) {
    e.preventDefault(); var u = document.getElementById("lu").value.trim(); var p = document.getElementById("lp").value;
    var errEl = document.getElementById("login-err"); if (!u || !p) { errEl.textContent = "请输入账号和密码"; return; }
    errEl.textContent = "登录中…";
    fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: u, password: p }) })
    .then(r => r.json().then(d => ({ ok: r.ok, d }))).then(res => {
      if (!res.ok) { errEl.textContent = res.d.error || "登录失败"; return; }
      token = res.d.token; user = res.d.username; role = res.d.role; localStorage.setItem("do-chat-token", token); startChat();
    }).catch(() => errEl.textContent = "网络错误");
  };

  document.getElementById("pwd-btn").onclick = () => { document.getElementById("pwd-msg").textContent = ""; pwdModal.style.display = "flex"; };
  document.getElementById("pwd-cancel").onclick = () => pwdModal.style.display = "none";
  document.getElementById("pwd-form").onsubmit = function (e) {
    e.preventDefault(); var oldP = document.getElementById("pw-old").value; var n1 = document.getElementById("pw-new").value; var n2 = document.getElementById("pw-new2").value;
    var msgEl = document.getElementById("pwd-msg"); msgEl.style.color = "#f87171";
    if (!oldP || !n1) { msgEl.textContent = "请填写完整"; return; } if (n1 !== n2) { msgEl.textContent = "两次输入的新密码不一致"; return; }
    msgEl.textContent = "提交中…";
    fetch("/api/change-password", { method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token }, body: JSON.stringify({ oldPassword: oldP, newPassword: n1 }) })
    .then(r => r.json().then(d => ({ ok: r.ok, d }))).then(res => {
      if (!res.ok) { msgEl.textContent = res.d.error || "修改失败"; return; }
      token = res.d.token; localStorage.setItem("do-chat-token", token); msgEl.style.color = "#4ade80"; msgEl.textContent = "✅ 修改成功";
      setTimeout(() => { pwdModal.style.display = "none"; document.getElementById("pw-old").value = ""; document.getElementById("pw-new").value = ""; document.getElementById("pw-new2").value = ""; }, 800);
    }).catch(() => msgEl.textContent = "网络错误");
  };

  document.getElementById("edit-notice-btn").onclick = function() {
    document.getElementById("notice-input").value = currentNoticeText; document.getElementById("notice-msg").textContent = ""; noticeModal.style.display = "flex";
  };
  document.getElementById("notice-cancel").onclick = () => noticeModal.style.display = "none";
  document.getElementById("notice-form").onsubmit = function(e) {
    e.preventDefault(); var text = document.getElementById("notice-input").value; var msgEl = document.getElementById("notice-msg"); msgEl.textContent = "发布中...";
    fetch("/api/notice", { method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token }, body: JSON.stringify({ text }) })
    .then(r => r.json()).then(res => { if (res.ok) noticeModal.style.display = "none"; else { msgEl.style.color = "#f87171"; msgEl.textContent = res.error; } }).catch(() => msgEl.textContent = "网络错误");
  };

  document.getElementById("edit-prompt-btn").onclick = function() {
    fetch("/api/prompt").then(r => r.json()).then(res => {
      document.getElementById("prompt-input").value = res.text || ""; document.getElementById("prompt-msg").textContent = ""; promptModal.style.display = "flex";
    });
  };
  document.getElementById("prompt-cancel").onclick = () => promptModal.style.display = "none";
  document.getElementById("prompt-form").onsubmit = function(e) {
    e.preventDefault(); var text = document.getElementById("prompt-input").value; var msgEl = document.getElementById("prompt-msg"); msgEl.textContent = "保存中...";
    fetch("/api/prompt", { method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token }, body: JSON.stringify({ text }) })
    .then(r => r.json()).then(res => { if (res.ok) { msgEl.style.color = "#4ade80"; msgEl.textContent = "✅ 保存成功"; setTimeout(() => promptModal.style.display = "none", 800); } else { msgEl.style.color = "#f87171"; msgEl.textContent = res.error; } }).catch(() => msgEl.textContent = "网络错误");
  };

  document.getElementById("manage-users-btn").onclick = function() {
    document.getElementById("user-msg").textContent = "加载中...";
    userModal.style.display = "flex";
    fetch("/api/users", { headers: { "Authorization": "Bearer " + token } })
      .then(r => r.json())
      .then(res => {
        if (res.users) { renderUserList(res.users); document.getElementById("user-msg").textContent = ""; }
        else { document.getElementById("user-msg").textContent = res.error || "加载失败"; }
      }).catch(() => document.getElementById("user-msg").textContent = "网络错误");
  };
  document.getElementById("user-cancel").onclick = () => userModal.style.display = "none";

  function renderUserList(users) {
    const tbody = document.getElementById("user-tbody");
    tbody.innerHTML = "";
    users.forEach(u => {
      const tr = document.createElement("tr");
      const isSuperAdmin = u.role === "admin";
      const isMe = u.username === user;
      
      tr.innerHTML = \`
        <td>\${u.username} \${isSuperAdmin ? '👑' : ''} \${isMe ? '(我)' : ''}</td>
        <td>\${isSuperAdmin ? '超管' : '普通'}</td>
        <td><label class="switch"><input type="checkbox" data-user="\${u.username}" data-perm="cmd" \${u.perms.cmd ? 'checked' : ''} \${isSuperAdmin ? 'disabled' : ''}><span class="slider"></span></label></td>
        <td><label class="switch"><input type="checkbox" data-user="\${u.username}" data-perm="notice" \${u.perms.notice ? 'checked' : ''} \${isSuperAdmin ? 'disabled' : ''}><span class="slider"></span></label></td>
        <td><label class="switch"><input type="checkbox" data-user="\${u.username}" data-perm="mute" \${u.perms.mute ? 'checked' : ''} \${isSuperAdmin ? 'disabled' : ''}><span class="slider"></span></label></td>
        <td><label class="switch"><input type="checkbox" data-user="\${u.username}" data-perm="ai" \${u.perms.ai ? 'checked' : ''} \${isSuperAdmin ? 'disabled' : ''}><span class="slider"></span></label></td>
        <td>
          <button class="act-btn mute" data-user="\${u.username}" data-muted="\${u.muted}" \${isSuperAdmin || (u.perms && u.perms.mute) ? 'disabled' : ''}>\${u.muted ? '解禁' : '禁言'}</button>
          <button class="act-btn reset" data-user="\${u.username}" \${isMe ? 'disabled' : ''}>重置密码</button>
          <button class="act-btn del" data-user="\${u.username}" \${isSuperAdmin || isMe ? 'disabled' : ''}>删除</button>
        </td>
      \`;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.onchange = function() {
        const u = this.dataset.user;
        const p = this.dataset.perm;
        const val = this.checked;
        const msgEl = document.getElementById("user-msg");
        msgEl.textContent = "保存中...";
        fetch("/api/manage", {
          method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
          body: JSON.stringify({ action: "set_perms", username: u, perms: { [p]: val } })
        }).then(r => r.json()).then(res => {
          msgEl.textContent = res.ok ? "✅ 权限已更新" : ("❌ " + res.error);
          msgEl.style.color = res.ok ? "#4ade80" : "#f87171";
          if (res.ok) document.getElementById("manage-users-btn").click(); // 刷新列表以更新按钮禁用状态
        }).catch(() => msgEl.textContent = "网络错误");
      };
    });

    tbody.querySelectorAll('.act-btn').forEach(btn => {
      btn.onclick = function() {
        const u = this.dataset.user;
        const msgEl = document.getElementById("user-msg");
        msgEl.style.color = "#f87171";
        
        if (this.classList.contains('mute')) {
          msgEl.textContent = "处理中...";
          fetch("/api/manage", {
            method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
            body: JSON.stringify({ action: "toggle_mute", username: u })
          }).then(r => r.json()).then(res => {
            if (res.ok) {
              this.dataset.muted = res.muted;
              this.textContent = res.muted ? "解禁" : "禁言";
              msgEl.textContent = "✅ 状态已更新"; msgEl.style.color = "#4ade80";
            } else { msgEl.textContent = "❌ " + res.error; }
          }).catch(() => msgEl.textContent = "网络错误");
        } 
        else if (this.classList.contains('reset')) {
          const newPwd = prompt("请输入 " + u + " 的新密码 (至少6位):");
          if (!newPwd) return;
          msgEl.textContent = "重置中...";
          fetch("/api/manage", {
            method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
            body: JSON.stringify({ action: "resetpw", username: u, password: newPwd })
          }).then(r => r.json()).then(res => {
            msgEl.textContent = res.ok ? "✅ 密码已重置" : ("❌ " + res.error);
            msgEl.style.color = res.ok ? "#4ade80" : "#f87171";
          }).catch(() => msgEl.textContent = "网络错误");
        }
        else if (this.classList.contains('del')) {
          if (!confirm("确定要彻底删除用户 " + u + " 吗？此操作不可逆！")) return;
          msgEl.textContent = "删除中...";
          fetch("/api/manage", {
            method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
            body: JSON.stringify({ action: "delete", username: u })
          }).then(r => r.json()).then(res => {
            if (res.ok) {
              msgEl.textContent = "✅ 用户已删除"; msgEl.style.color = "#4ade80";
              document.getElementById("manage-users-btn").click();
            } else { msgEl.textContent = "❌ " + res.error; }
          }).catch(() => msgEl.textContent = "网络错误");
        }
      };
    });
  }

  function startChat() {
    loginEl.style.display = "none"; appEl.style.display = "flex";
    document.getElementById("me").textContent = (role === "admin" ? "👑 " : "") + user;
    if (role === "admin") {
      document.getElementById("edit-notice-btn").style.display = "inline-block";
      document.getElementById("edit-prompt-btn").style.display = "inline-block";
      document.getElementById("manage-users-btn").style.display = "inline-block";
    }
    fetch("/api/notice").then(r => r.json()).then(res => { if (res.text) renderNotice(res.text); }).catch(() => {});
    connect();
  }

  function renderNotice(text) {
    currentNoticeText = text || ""; if (!text) { noticeContainer.style.display = "none"; return; }
    noticeContainer.style.display = "block"; noticeContent.innerHTML = renderContent(text);
  }

  function connect() {
    var proto = location.protocol === "https:" ? "wss://" : "ws://";
    ws = new WebSocket(proto + location.host + "/ws?token=" + encodeURIComponent(token));
    ws.onopen = () => dotEl.classList.add("on");
    ws.onmessage = function (event) {
      var data = JSON.parse(event.data);
      switch (data.type) {
        case "history": data.messages.forEach(addMessage); break;
        case "message": addMessage(data); break;
        case "system": addSystem(data.text); break;
        case "online": onlineEl.textContent = "在线 (" + data.users.length + "): " + data.users.join(", "); break;
        case "clear": messagesEl.innerHTML = ""; addSystem("聊天记录已清空"); break;
        case "kicked": alert(data.reason || "你已被移出聊天室"); logout(); break;
        case "notice": renderNotice(data.text); break;
      }
    };
    ws.onclose = function (e) {
      dotEl.classList.remove("on"); if (e.code === 4001) return;
      fetch("/api/me?token=" + encodeURIComponent(token)).then(r => { if (r.status === 401) logout(); else setTimeout(connect, 2000); }).catch(() => setTimeout(connect, 2000));
    };
  }

  function addSystem(text) { var div = document.createElement("div"); div.className = "sys"; div.textContent = text; messagesEl.appendChild(div); messagesEl.scrollTop = messagesEl.scrollHeight; }

  function addMessage(m) {
    var div = document.createElement("div");
    var cls = "msg"; if (m.role === "bot") cls += " bot"; else if (m.user === user) cls += " mine";
    div.className = cls;
    var meta = document.createElement("div"); meta.className = "meta";
    var prefix = m.role === "admin" ? "👑 " : (m.role === "bot" ? "🤖 " : "");
    meta.textContent = prefix + m.user + " · " + new Date(m.time).toLocaleTimeString();
    var body = document.createElement("div"); body.className = "msg-body"; body.innerHTML = renderContent(m.text);
    div.appendChild(meta); div.appendChild(body); messagesEl.appendChild(div); messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  document.getElementById("form").onsubmit = function (e) {
    e.preventDefault(); var text = inputEl.value.trim(); if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ text: text })); inputEl.value = "";
  };

  var saved = localStorage.getItem("do-chat-token");
  if (saved) {
    token = saved; fetch("/api/me?token=" + encodeURIComponent(token)).then(r => {
      if (!r.ok) { localStorage.removeItem("do-chat-token"); showLogin(); return; }
      return r.json().then(d => { user = d.username; role = d.role; startChat(); });
    }).catch(() => showLogin());
  } else { showLogin(); }
})();
</script>
</body>
</html>`;