const assert = require('assert');
const fetch = global.fetch || require('node-fetch');

const BASE = 'http://localhost:3000';
// Read Firebase DB URL from public/main.js
const mainJs = require('fs').readFileSync(__dirname + '/../public/main.js', 'utf8');
const dbUrlMatch = mainJs.match(/databaseURL:\s*"([^"]+)"/);
if (!dbUrlMatch) {
  console.error('Could not find databaseURL in public/main.js');
  process.exit(1);
}
const FIREBASE_DB = dbUrlMatch[1];

async function postJson(url, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  return res;
}

async function getJson(url, token) {
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(url, { headers });
  return res;
}

(async () => {
  try {
    console.log('Starting API tests against', BASE);

    // 1) Signup two users
    const u1 = 'api_user_a_' + Date.now();
    const u2 = 'api_user_b_' + Date.now();

    let res = await postJson(`${BASE}/signup`, { username: u1, password: 'pass123' });
    assert.strictEqual(res.status, 200, 'signup u1 failed');
    const data1 = await res.json();
    console.log('Signed up', data1.username);

    res = await postJson(`${BASE}/signup`, { username: u2, password: 'pass123' });
    assert.strictEqual(res.status, 200, 'signup u2 failed');
    const data2 = await res.json();
    console.log('Signed up', data2.username);

    // 2) Login both
    res = await postJson(`${BASE}/login`, { username: data1.username, password: 'pass123' });
    assert.strictEqual(res.status, 200, 'login u1 failed');
    const login1 = await res.json();
    console.log('Logged in', login1.username);

    res = await postJson(`${BASE}/login`, { username: data2.username, password: 'pass123' });
    assert.strictEqual(res.status, 200, 'login u2 failed');
    const login2 = await res.json();
    console.log('Logged in', login2.username);

    // 3) Create group as user1 with member user2
    res = await postJson(`${BASE}/group/create`, { groupName: 'apitestgroup', memberUsernames: [data2.username] }, login1.token);
    assert.strictEqual(res.status, 200, 'group create failed');
    const group = await res.json();
    console.log('Group created', group.groupId);

    // 4) Post a group message as user1
    res = await postJson(`${BASE}/group/${group.groupId}/message`, { text: 'Hello group via API' }, login1.token);
    assert.strictEqual(res.status, 200, 'post group message failed');
    const gm = await res.json();
    console.log('Group message posted:', gm.text);

    // 5) Retrieve group messages as user2
    res = await getJson(`${BASE}/group/${group.groupId}/messages`, login2.token);
    assert.strictEqual(res.status, 200, 'get group messages failed');
    const msgs = await res.json();
    assert(msgs.some(m => m.text === 'Hello group via API'), 'group message not found');
    console.log('Group message observed by user2');

    // 6) Direct message via Firebase REST: push a message into messages/{conversationKey}
    const convKey = [data1.userId, data2.userId].sort().join('_');
    const fbPushUrl = `${FIREBASE_DB}/messages/${convKey}.json`;
    const msg = { sender: data1.username, senderUserId: data1.userId, text: 'Hello direct via REST', ts: Date.now() };
    res = await fetch(fbPushUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(msg) });
    assert.strictEqual(res.status, 200, 'firebase push failed');
    const pushResp = await res.json();
    console.log('Pushed direct message to Firebase with name', pushResp.name);

    // Read back the messages list
    const fbGetUrl = `${FIREBASE_DB}/messages/${convKey}.json?orderBy="ts"`;
    res = await fetch(fbGetUrl);
    assert.strictEqual(res.status, 200, 'firebase get failed');
    const convo = await res.json();
    const found = Object.values(convo || {}).some(m => m.text === msg.text);
    assert(found, 'direct message not found in Firebase');
    console.log('Direct message confirmed in Firebase');

    // 7) Self delete user2
    res = await postJson(`${BASE}/delete-account`, { targetUsername: data2.username }, login2.token);
    assert.strictEqual(res.status, 200, 'self delete failed');
    console.log('Self-deleted', data2.username);

    // 8) Admin login and delete user1
    res = await postJson(`${BASE}/login`, { username: 'admin', password: 'jeremy0106' });
    assert.strictEqual(res.status, 200, 'admin login failed');
    const admin = await res.json();
    res = await postJson(`${BASE}/admin/delete-user`, { username: data1.username }, admin.token);
    assert.strictEqual(res.status, 200, 'admin delete failed');
    console.log('Admin deleted', data1.username);

    console.log('All API tests passed');
    process.exit(0);
  } catch (err) {
    console.error('API tests failed:', err);
    process.exit(2);
  }
})();
