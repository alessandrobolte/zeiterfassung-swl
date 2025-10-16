export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // --- 🔹 loadData ---
    if (url.pathname === "/functions/loadData") {
      try {
        const data = await env.ZM_BUCKET.get("data.json", { type: "json" });
        return new Response(JSON.stringify(data || {}), {
          headers: { "Content-Type": "application/json" },
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: err.message }),
          { status: 500, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // --- 🔹 saveData ---
    if (url.pathname === "/functions/saveData") {
      try {
        const body = await request.json();
        await env.ZM_BUCKET.put("data.json", JSON.stringify(body, null, 2));
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" },
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: err.message }),
          { status: 500, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // --- 🔹 alle anderen Requests → index.html ---
    return env.ASSETS.fetch(request);
  },
};
// _worker_auth_example.js
// Annahme: BINDINGS -> KV Namespaces: USERS_KV, TIMES_KV, SESSIONS_KV
// und env.JWT_SECRET (wenn nötig). Anpassungen ggf. an wrangler.json

addEventListener('fetch', event => {
  event.respondWith(handle(event.request));
});

const LEM_PROJECT = "LemGOesHANA";

async function handle(request){
  const url = new URL(request.url);
  if (url.pathname === '/api/login' && request.method === 'POST') return handleLogin(request);
  if (url.pathname === '/api/change-password' && request.method === 'POST') return handleChangePassword(request);
  if (url.pathname === '/api/user/data' && request.method === 'GET') return withAuth(request, handleGetUserData);
  if (url.pathname === '/api/user/times' && request.method === 'POST') return withAuth(request, handlePostTime);
  if (url.pathname === '/api/admin/lemgoeshana' && request.method === 'GET') return withAuth(request, handleAdminLem);
  return new Response('Not Found', {status:404});
}

// util: read cookie
function parseCookies(cookieHeader){
  const cookies = {};
  if(!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(c => {
    const [k,v] = c.split('=').map(s=>s.trim());
    if(k) cookies[k]=v;
  });
  return cookies;
}

async function withAuth(request, handler){
  const cookie = parseCookies(request.headers.get('cookie'));
  const token = cookie.session;
  if(!token) return new Response(JSON.stringify({error:'unauthenticated'}), {status:401});
  const sessRaw = await SESSIONS_KV.get(`session:${token}`);
  if(!sessRaw) return new Response(JSON.stringify({error:'session invalid'}), {status:401});
  const sess = JSON.parse(sessRaw);
  if(Date.now() > sess.expires) {
    await SESSIONS_KV.delete(`session:${token}`);
    return new Response(JSON.stringify({error:'session expired'}), {status:401});
  }
  // attach user
  request.user = sess.username;
  return handler(request, sess.username);
}

// Login handler
async function handleLogin(request){
  const body = await request.json();
  const {username, password} = body || {};
  if(!username || !password) return new Response(JSON.stringify({error:'missing'}), {status:400});
  const userRaw = await USERS_KV.get(`user:${username}`);
  if(!userRaw) return new Response(JSON.stringify({error:'invalid'}), {status:401});
  const user = JSON.parse(userRaw);
  const hash = await sha256Hex(user.salt + password);
  if(hash !== user.hash) return new Response(JSON.stringify({error:'invalid'}), {status:401});

  // create session token
  const token = crypto.getRandomValues(new Uint8Array(24)).reduce((s,b)=>s+b.toString(16).padStart(2,'0'),'');
  const expires = Date.now() + 24*60*60*1000; // 24h
  await SESSIONS_KV.put(`session:${token}`, JSON.stringify({username, expires}), {expiration: Math.floor(expires/1000)});
  const headers = {
    'Set-Cookie': `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${24*60*60}`,
    'Content-Type': 'application/json'
  };
  return new Response(JSON.stringify({ok:true, mustChangePassword: !!user.mustChangePassword, role: user.role}), {status:200, headers});
}

// change-password
async function handleChangePassword(request, username){
  const body = await request.json();
  const {oldPassword, newPassword} = body || {};
  const userRaw = await USERS_KV.get(`user:${username}`);
  if(!userRaw) return new Response(JSON.stringify({error:'no user'}), {status:400});
  const user = JSON.parse(userRaw);

  // if mustChangePassword and no oldPassword required, skip old check
  if(!user.mustChangePassword){
    // verify oldPassword
    const oldHash = await sha256Hex(user.salt + (oldPassword||''));
    if(oldHash !== user.hash) return new Response(JSON.stringify({error:'invalid old password'}), {status:401});
  }

  const newSalt = crypto.getRandomValues(new Uint8Array(16)).reduce((s,b)=>s+b.toString(16).padStart(2,'0'),'');
  const newHash = await sha256Hex(newSalt + newPassword);
  user.salt = newSalt;
  user.hash = newHash;
  user.mustChangePassword = false;
  await USERS_KV.put(`user:${username}`, JSON.stringify(user));
  return new Response(JSON.stringify({ok:true}), {status:200, headers:{'Content-Type':'application/json'}});
}

// example: get user data
async function handleGetUserData(request, username){
  const userRaw = await USERS_KV.get(`user:${username}`);
  const timesRaw = await TIMES_KV.get(`times:${username}`);
  const user = userRaw ? JSON.parse(userRaw) : null;
  const times = timesRaw ? JSON.parse(timesRaw) : [];
  return new Response(JSON.stringify({user, times}), {status:200, headers:{'Content-Type':'application/json'}});
}

// posting times (append)
async function handlePostTime(request, username){
  // body contains full action: add/update/delete
  const body = await request.json();
  const timesRaw = await TIMES_KV.get(`times:${username}`);
  let times = timesRaw ? JSON.parse(timesRaw) : [];
  if(body.action === 'add'){
    times.push(body.entry);
  } else if(body.action === 'update'){
    times = times.map(t=> t.id===body.entry.id ? body.entry : t);
  } else if(body.action === 'delete'){
    times = times.filter(t=> t.id !== body.id);
  }
  await TIMES_KV.put(`times:${username}`, JSON.stringify(times));
  return new Response(JSON.stringify({ok:true}), {status:200, headers:{'Content-Type':'application/json'}});
}

// admin: get all users' LemGOesHANA entries
async function handleAdminLem(request, username){
  const userRaw = await USERS_KV.get(`user:${username}`);
  if(!userRaw) return new Response(JSON.stringify({error:'no user'}), {status:401});
  const user = JSON.parse(userRaw);
  if(user.role !== 'admin') return new Response(JSON.stringify({error:'forbidden'}), {status:403});
  // list all users (we'll need to store an index key or keep a user list)
  const usersIndexRaw = await USERS_KV.get('users:index');
  const usersList = usersIndexRaw ? JSON.parse(usersIndexRaw) : [];
  const result = [];
  for(const u of usersList){
    const timesRaw = await TIMES_KV.get(`times:${u}`);
    const times = timesRaw ? JSON.parse(timesRaw) : [];
    const filtered = times.filter(t => t.project === LEM_PROJECT);
    if(filtered.length) result.push({username: u, times: filtered});
  }
  return new Response(JSON.stringify({ok:true, data: result}), {status:200, headers:{'Content-Type':'application/json'}});
}

/* helper: sha256 as hex string */
async function sha256Hex(message){
  const enc = new TextEncoder();
  const data = enc.encode(message);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuf));
  return hashArray.map(b => b.toString(16).padStart(2,'0')).join('');
}
