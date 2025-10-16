/**
 * worker.js – Zeiterfassung mit Benutzerverwaltung
 * Cloudflare KV Bindings:
 * - USERS_KV
 * - TIMES_KV
 * - SESSIONS_KV
 * 
 * Env:
 * - INIT_SECRET = dein_setup_passwort (z. B. "setup123")
 */

const LEM_PROJECT = "LemGOesHANA";
const SESSION_TTL_SECONDS = 24 * 60 * 60; // 24 Stunden

addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const { pathname } = url;

  // API-Endpunkte
  if (pathname === "/api/login" && request.method === "POST")
    return handleLogin(request);
  if (pathname === "/api/change-password" && request.method === "POST")
    return withAuth(request, handleChangePassword);
  if (pathname === "/api/user/data" && request.method === "GET")
    return withAuth(request, handleGetUserData);
  if (pathname === "/api/user/times" && request.method === "POST")
    return withAuth(request, handlePostTime);
  if (pathname === "/api/admin/lemgoeshana" && request.method === "GET")
    return withAuth(request, handleAdminLem);

  // einmaliges Setup (Initialbenutzer anlegen)
  if (pathname === "/api/setup" && request.method === "POST")
    return handleSetup(request);

  return new Response("Not found", { status: 404 });
}

/* ---------- Hilfsfunktionen ---------- */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(";").forEach(c => {
    const [k, v] = c.split("=").map(x => x.trim());
    if (k) cookies[k] = v;
  });
  return cookies;
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomHex(len = 16) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

/* ---------- Auth-Wrapper ---------- */

async function withAuth(request, handler) {
  const cookies = parseCookies(request.headers.get("cookie"));
  const token = cookies.session;
  if (!token) return json({ error: "unauthorized" }, 401);

  const sessRaw = await SESSIONS_KV.get(`session:${token}`);
  if (!sessRaw) return json({ error: "invalid session" }, 401);

  const sess = JSON.parse(sessRaw);
  if (Date.now() > sess.expires) {
    await SESSIONS_KV.delete(`session:${token}`);
    return json({ error: "session expired" }, 401);
  }

  request.user = sess.username;
  return handler(request, sess.username);
}

/* ---------- LOGIN ---------- */

async function handleLogin(request) {
  const { username, password } = await request.json();
  const userRaw = await USERS_KV.get(`user:${username}`);
  if (!userRaw) return json({ error: "invalid credentials" }, 401);

  const user = JSON.parse(userRaw);
  const hash = await sha256Hex(user.salt + password);
  if (hash !== user.hash) return json({ error: "invalid credentials" }, 401);

  // Session erstellen
  const token = randomHex(24);
  const expires = Date.now() + SESSION_TTL_SECONDS * 1000;
  await SESSIONS_KV.put(
    `session:${token}`,
    JSON.stringify({ username, expires }),
    { expirationTtl: SESSION_TTL_SECONDS }
  );

  const headers = {
    "Set-Cookie": `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_SECONDS}`,
    "Content-Type": "application/json",
  };

  return new Response(
    JSON.stringify({
      ok: true,
      mustChangePassword: user.mustChangePassword,
      role: user.role,
    }),
    { headers }
  );
}

/* ---------- PASSWORT ÄNDERN ---------- */

async function handleChangePassword(request, username) {
  const { oldPassword, newPassword } = await request.json();
  const userRaw = await USERS_KV.get(`user:${username}`);
  if (!userRaw) return json({ error: "user not found" }, 400);

  const user = JSON.parse(userRaw);
  if (!user.mustChangePassword) {
    const oldHash = await sha256Hex(user.salt + oldPassword);
    if (oldHash !== user.hash) return json({ error: "wrong password" }, 401);
  }

  const newSalt = randomHex(16);
  const newHash = await sha256Hex(newSalt + newPassword);
  user.salt = newSalt;
  user.hash = newHash;
  user.mustChangePassword = false;

  await USERS_KV.put(`user:${username}`, JSON.stringify(user));
  return json({ ok: true });
}

/* ---------- USER-DATEN ---------- */

async function handleGetUserData(request, username) {
  const userRaw = await USERS_KV.get(`user:${username}`);
  const timesRaw = await TIMES_KV.get(`times:${username}`);

  const user = userRaw ? JSON.parse(userRaw) : {};
  const times = timesRaw ? JSON.parse(timesRaw) : [];

  return json({ user, times });
}

/* ---------- ZEITEN SPEICHERN ---------- */

async function handlePostTime(request, username) {
  const body = await request.json();
  const { action, entry } = body;

  let times = [];
  const timesRaw = await TIMES_KV.get(`times:${username}`);
  if (timesRaw) times = JSON.parse(timesRaw);

  if (action === "add") times.push(entry);
  if (action === "update")
    times = times.map(t => (t.id === entry.id ? entry : t));
  if (action === "delete")
    times = times.filter(t => t.id !== entry.id);

  await TIMES_KV.put(`times:${username}`, JSON.stringify(times));
  return json({ ok: true });
}

/* ---------- ADMIN: LemGOesHANA ---------- */

async function handleAdminLem(request, username) {
  const adminRaw = await USERS_KV.get(`user:${username}`);
  const admin = adminRaw ? JSON.parse(adminRaw) : null;
  if (!admin || admin.role !== "admin")
    return json({ error: "forbidden" }, 403);

  const userIndexRaw = await USERS_KV.get("users:index");
  const users = userIndexRaw ? JSON.parse(userIndexRaw) : [];
  const result = [];

  for (const u of users) {
    const timesRaw = await TIMES_KV.get(`times:${u}`);
    const times = timesRaw ? JSON.parse(timesRaw) : [];
    const filtered = times.filter(t => t.project === LEM_PROJECT);
    if (filtered.length > 0) result.push({ username: u, times: filtered });
  }

  return json({ ok: true, data: result });
}

/* ---------- SETUP ---------- */
/**
 * einmaliges Initialisieren aller Benutzer (11 Accounts)
 * aufruf: POST /api/setup  mit Header x-secret: INIT_SECRET
 */

async function handleSetup(request) {
  const secret = request.headers.get("x-secret");
  if (secret !== INIT_SECRET) return json({ error: "unauthorized" }, 401);

  const initUsers = [
    { username: "admin", role: "admin" },
    { username: "alessandro", role: "user" },
    { username: "michael", role: "user" },
    { username: "dominik", role: "user" },
    { username: "christiane", role: "user" },
    { username: "fabian", role: "user" },
    { username: "kati", role: "user" },
    { username: "denise", role: "user" },
    { username: "philip", role: "user" },
    { username: "marcel", role: "user" },
    { username: "yannik", role: "user" },
  ];

  const password = "Stadtwerke1";
  const usersIndex = [];

  for (const u of initUsers) {
    const salt = randomHex(16);
    const hash = await sha256Hex(salt + password);

    const userObj = {
      username: u.username,
      role: u.role,
      salt,
      hash,
      mustChangePassword: true,
      projects: [{ name: LEM_PROJECT, deletable: false }],
    };

    await USERS_KV.put(`user:${u.username}`, JSON.stringify(userObj));
    usersIndex.push(u.username);
  }

  await USERS_KV.put("users:index", JSON.stringify(usersIndex));

  return json({ ok: true, users: usersIndex });
}
