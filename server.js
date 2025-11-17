const express = require('express');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// JWT secret (set in Vercel env as JWT_SECRET). Use a default for local dev.
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';

// Try to discover Firebase Realtime Database URL from client config so server can use the DB
// Allow explicit override via env var (recommended). Otherwise try to infer from public/main.js
let FIREBASE_DB_URL = process.env.FIREBASE_DB_URL || null;
if (!FIREBASE_DB_URL) {
  try {
    const clientJs = require('fs').readFileSync(path.join(__dirname, 'public', 'main.js'), 'utf8');
    const m = clientJs.match(/databaseURL:\s*"([^"]+)"/);
    if (m) FIREBASE_DB_URL = m[1].replace(/"|\s/g, '');
  } catch (err) {
    // ignore
  }
}

async function firebaseGet(path) {
  if (!FIREBASE_DB_URL) return null;
  const url = `${FIREBASE_DB_URL.replace(/\/$/, '')}${path}.json`;
  const res = await fetch(url);
  if (!res.ok) return null;
  return res.json();
}

async function firebasePut(path, obj) {
  if (!FIREBASE_DB_URL) return null;
  const url = `${FIREBASE_DB_URL.replace(/\/$/, '')}${path}.json`;
  const res = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });
  return res.ok ? res.json() : null;
}

async function firebasePost(path, obj) {
  if (!FIREBASE_DB_URL) return null;
  const url = `${FIREBASE_DB_URL.replace(/\/$/, '')}${path}.json`;
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });
  return res.ok ? res.json() : null;
}

async function firebaseDelete(path) {
  if (!FIREBASE_DB_URL) return null;
  const url = `${FIREBASE_DB_URL.replace(/\/$/, '')}${path}.json`;
  const res = await fetch(url, { method: 'DELETE' });
  return res.ok;
}

// Admin account (local credential)
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD_HASH = crypto.createHash('sha256').update('jeremy0106').digest('hex');

function hashPassword(pwd) {
  return crypto.createHash('sha256').update(pwd).digest('hex');
}

function generateUserId() {
  return crypto.randomBytes(8).toString('hex');
}

function generateGroupId() {
  return 'group_' + crypto.randomBytes(8).toString('hex');
}

// Helpers for user storage in Firebase
async function getUser(username) {
  return await firebaseGet(`/users/${encodeURIComponent(username)}`);
}

async function setUser(username, obj) {
  return await firebasePut(`/users/${encodeURIComponent(username)}`, obj);
}

async function deleteUser(username) {
  return await firebaseDelete(`/users/${encodeURIComponent(username)}`);
}

async function listUsers() {
  const obj = await firebaseGet('/users') || {};
  return Object.entries(obj).map(([k, v]) => ({ username: k, userId: v.userId, createdAt: v.createdAt, isAdmin: v.isAdmin || false }));
}

// Ensure unique username with auto-numbering (checks Firebase)
async function getUniqueUsername(baseUsername) {
  const base = baseUsername.toLowerCase();
  let candidate = base;
  let counter = 2;
  while (await getUser(candidate)) {
    candidate = base + counter;
    counter++;
  }
  return candidate;
}

// POST /signup
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.toLowerCase() === ADMIN_USERNAME) return res.status(400).json({ error: 'Username reserved' });

  const uniqueUsername = await getUniqueUsername(username);
  const userId = generateUserId();
  const hashedPwd = hashPassword(password);
  const userObj = { userId, password: hashedPwd, createdAt: Date.now(), isAdmin: false };
  await setUser(uniqueUsername, userObj);

  // Mirror into client-visible users path (clients also write but keep this for consistency)
  // generate JWT
  const token = jwt.sign({ userId, username: uniqueUsername, isAdmin: false }, JWT_SECRET, { expiresIn: '30d' });

  // Also write a shallow public profile for realtime users listing
  try { await firebasePut(`/users_public/${encodeURIComponent(uniqueUsername)}`, { userId, username: uniqueUsername, createdAt: userObj.createdAt }); } catch (e) {}

  res.json({ token, userId, username: uniqueUsername });
});

// POST /login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  // admin check
  if (username === ADMIN_USERNAME) {
    const hashed = hashPassword(password);
    if (hashed !== ADMIN_PASSWORD_HASH) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: 'admin', username: ADMIN_USERNAME, isAdmin: true }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ token, userId: 'admin', username: ADMIN_USERNAME, isAdmin: true });
  }

  const user = await getUser(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const hashed = hashPassword(password);
  if (user.password !== hashed) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.userId, username, isAdmin: false }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, userId: user.userId, username });
});

// auth middleware (verify JWT)
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.session = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// GET /users (public list)
app.get('/users', async (req, res) => {
  const users = await listUsers();
  res.json(users.map(u => ({ username: u.username, userId: u.userId, createdAt: u.createdAt })));
});

// POST /delete-account
app.post('/delete-account', authMiddleware, async (req, res) => {
  const { targetUsername } = req.body;
  if (!targetUsername) return res.status(400).json({ error: 'Target username required' });
  if (!req.session.isAdmin && req.session.username !== targetUsername) return res.status(403).json({ error: 'Permission denied' });

  const exists = await getUser(targetUsername);
  if (!exists) return res.status(404).json({ error: 'User not found' });
  await deleteUser(targetUsername);
  await firebaseDelete(`/users_public/${encodeURIComponent(targetUsername)}`).catch(()=>{});
  res.json({ message: `User ${targetUsername} deleted successfully` });
});

// POST /logout - client can simply discard token; keep endpoint for compatibility
app.post('/logout', authMiddleware, (req, res) => {
  res.json({ message: 'Logged out' });
});

// GROUPS: store groups under /groups and messages under /groupMessages
app.post('/group/create', authMiddleware, async (req, res) => {
  const { groupName, memberUsernames } = req.body;
  if (!groupName) return res.status(400).json({ error: 'Group name required' });
  const groupId = generateGroupId();
  const members = [req.session.username, ...(memberUsernames || [])];
  const groupObj = { groupId, name: groupName, members, createdAt: Date.now(), createdBy: req.session.username };
  await firebasePut(`/groups/${groupId}`, groupObj);
  await firebasePut(`/groupMessages/${groupId}`, {});
  res.json(groupObj);
});

app.get('/groups', authMiddleware, async (req, res) => {
  const obj = await firebaseGet('/groups') || {};
  const groups = Object.values(obj).filter(g => g.members && g.members.includes(req.session.username));
  res.json(groups);
});

app.post('/group/:groupId/message', authMiddleware, async (req, res) => {
  const { groupId } = req.params;
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Message text required' });
  const group = await firebaseGet(`/groups/${groupId}`);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (!group.members.includes(req.session.username)) return res.status(403).json({ error: 'Not a member' });
  const message = { sender: req.session.username, senderUserId: req.session.userId, text, ts: Date.now() };
  await firebasePost(`/groupMessages/${groupId}`, message);
  res.json(message);
});

app.get('/group/:groupId/messages', authMiddleware, async (req, res) => {
  const { groupId } = req.params;
  const group = await firebaseGet(`/groups/${groupId}`);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (!group.members.includes(req.session.username)) return res.status(403).json({ error: 'Not a member' });
  const msgsObj = await firebaseGet(`/groupMessages/${groupId}`) || {};
  const msgs = Object.values(msgsObj || {});
  res.json(msgs);
});

// ADMIN endpoints
app.get('/admin/users', authMiddleware, async (req, res) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin only' });
  const users = await listUsers();
  res.json(users.map(u => ({ username: u.username, userId: u.userId, createdAt: u.createdAt })));
});

app.post('/admin/delete-user', authMiddleware, async (req, res) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin only' });
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });
  const exists = await getUser(username);
  if (!exists) return res.status(404).json({ error: 'User not found' });
  await deleteUser(username);
  await firebaseDelete(`/users_public/${encodeURIComponent(username)}`).catch(()=>{});
  res.json({ message: `User ${username} deleted by admin` });
});

app.get('/admin/message-history', authMiddleware, async (req, res) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin only' });
  const msgs = await firebaseGet('/messages') || {};
  res.json(msgs);
});

app.get('/admin/group-history', authMiddleware, async (req, res) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin only' });
  const groups = await firebaseGet('/groups') || {};
  const groupMsgs = await firebaseGet('/groupMessages') || {};
  const out = Object.entries(groupMsgs).map(([groupId, msgs]) => ({ groupId, groupInfo: groups[groupId], messages: Object.values(msgs || {}) }));
  res.json(out);
});

app.get('/health', (req, res) => res.send('ok'));

// Export app so Vercel can mount it in a serverless function. If run directly, start server.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Admin account: ${ADMIN_USERNAME} / password: jeremy0106`);
  });
}

module.exports = app;
const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory stores
const users = {};
const sessions = {};
const messageHistory = {}; // { conversationKey: [messages] }
const groupChats = {}; // { groupId: { name, members, createdAt, createdBy } }
const groupMessages = {}; // { groupId: [messages] }

// Try to discover Firebase Realtime Database URL from client config so server can mirror user presence
let FIREBASE_DB_URL = null;
try {
  const clientJs = require('fs').readFileSync(path.join(__dirname, 'public', 'main.js'), 'utf8');
  const m = clientJs.match(/databaseURL:\s*"([^"]+)"/);
  if (m) FIREBASE_DB_URL = m[1].replace(/"|\s/g, '');
} catch (err) {
  // ignore
}

async function writeFirebaseUser(username, data) {
  if (!FIREBASE_DB_URL) return;
  try {
    const url = `${FIREBASE_DB_URL.replace(/\/$/, '')}/users/${username}.json`;
    await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  } catch (err) {
    console.error('Failed writing user to Firebase', err.message || err);
  }
}

async function removeFirebaseUser(username) {
  if (!FIREBASE_DB_URL) return;
  try {
    const url = `${FIREBASE_DB_URL.replace(/\/$/, '')}/users/${username}.json`;
    await fetch(url, { method: 'DELETE' });
  } catch (err) {
    console.error('Failed removing user from Firebase', err.message || err);
  }
}

// Admin account
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD_HASH = crypto.createHash('sha256').update('jeremy0106').digest('hex');

// Note: we intentionally reserve the 'admin' username. Do not allow creating/removing it here.

function hashPassword(pwd) {
  return crypto.createHash('sha256').update(pwd).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateUserId() {
  return crypto.randomBytes(8).toString('hex');
}

function generateGroupId() {
  return 'group_' + crypto.randomBytes(8).toString('hex');
}

// Get unique username with auto-numbering
function getUniqueUsername(baseUsername) {
  const base = baseUsername.toLowerCase();
  if (!users[base]) {
    return base;
  }
  let counter = 2;
  while (users[base + counter]) {
    counter++;
  }
  return base + counter;
}

// POST /signup - register new user with auto-numbering
app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // Prevent creating the reserved admin username via signup
  if (username.toLowerCase() === ADMIN_USERNAME) {
    return res.status(400).json({ error: 'Username reserved' });
  }

  const uniqueUsername = getUniqueUsername(username);
  const userId = generateUserId();
  const hashedPwd = hashPassword(password);

  users[uniqueUsername] = {
    userId,
    password: hashedPwd,
    createdAt: Date.now(),
    isAdmin: false
  };

  const token = generateToken();
  sessions[token] = { userId, username: uniqueUsername, createdAt: Date.now(), isAdmin: false };

  // Mirror user into Firebase Realtime Database so clients can listen for joins
  writeFirebaseUser(uniqueUsername, { userId, username: uniqueUsername, createdAt: users[uniqueUsername].createdAt });

  res.json({ token, userId, username: uniqueUsername });
});

// POST /login - authenticate user (admin or regular)
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // Check if admin
  if (username === ADMIN_USERNAME) {
    const hashedPwd = hashPassword(password);
    if (hashedPwd !== ADMIN_PASSWORD_HASH) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = generateToken();
    sessions[token] = { userId: 'admin', username: ADMIN_USERNAME, createdAt: Date.now(), isAdmin: true };
    return res.json({ token, userId: 'admin', username: ADMIN_USERNAME, isAdmin: true });
  }

  // Check regular users
  const user = users[username];
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const hashedPwd = hashPassword(password);
  if (user.password !== hashedPwd) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = generateToken();
  sessions[token] = { userId: user.userId, username, createdAt: Date.now(), isAdmin: false };

  res.json({ token, userId: user.userId, username });
});

// GET /users - list all users
app.get('/users', (req, res) => {
  const userList = Object.entries(users).map(([username, data]) => ({
    username,
    userId: data.userId,
    createdAt: data.createdAt
  }));
  res.json(userList);
});

// Middleware to verify token
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token || !sessions[token]) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.session = sessions[token];
  next();
}

// POST /delete-account - delete user account (only self or admin)
app.post('/delete-account', authMiddleware, (req, res) => {
  const { targetUsername } = req.body;

  if (!targetUsername) {
    return res.status(400).json({ error: 'Target username required' });
  }

  // Only admin or self can delete
  if (!req.session.isAdmin && req.session.username !== targetUsername) {
    return res.status(403).json({ error: 'Permission denied' });
  }

  if (!users[targetUsername]) {
    return res.status(404).json({ error: 'User not found' });
  }

  delete users[targetUsername];

  // Invalidate sessions for deleted user
  Object.keys(sessions).forEach(token => {
    if (sessions[token].username === targetUsername) {
      delete sessions[token];
    }
  });

  // Remove from Firebase mirror as well
  removeFirebaseUser(targetUsername);

  res.json({ message: `User ${targetUsername} deleted successfully` });
});

// POST /logout - invalidate token
app.post('/logout', authMiddleware, (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  delete sessions[token];
  res.json({ message: 'Logged out' });
});

// POST /group/create - create a group chat
app.post('/group/create', authMiddleware, (req, res) => {
  const { groupName, memberUsernames } = req.body;

  if (!groupName) {
    return res.status(400).json({ error: 'Group name required' });
  }

  const groupId = generateGroupId();
  const members = [req.session.username, ...(memberUsernames || [])];
  
  groupChats[groupId] = {
    groupId,
    name: groupName,
    members,
    createdAt: Date.now(),
    createdBy: req.session.username
  };

  groupMessages[groupId] = [];

  res.json({ groupId, name: groupName, members, createdAt: groupChats[groupId].createdAt });
});

// GET /groups - list groups for current user
app.get('/groups', authMiddleware, (req, res) => {
  const userGroups = Object.values(groupChats).filter(g => 
    g.members.includes(req.session.username)
  );
  res.json(userGroups);
});

// POST /group/:groupId/message - send group message
app.post('/group/:groupId/message', authMiddleware, (req, res) => {
  const { groupId } = req.params;
  const { text } = req.body;

  if (!text) {
    return res.status(400).json({ error: 'Message text required' });
  }

  const group = groupChats[groupId];
  if (!group) {
    return res.status(404).json({ error: 'Group not found' });
  }

  if (!group.members.includes(req.session.username)) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }

  const message = {
    sender: req.session.username,
    senderUserId: req.session.userId,
    text,
    ts: Date.now()
  };

  if (!groupMessages[groupId]) {
    groupMessages[groupId] = [];
  }
  groupMessages[groupId].push(message);

  res.json(message);
});

// GET /group/:groupId/messages - get group message history
app.get('/group/:groupId/messages', authMiddleware, (req, res) => {
  const { groupId } = req.params;
  const group = groupChats[groupId];

  if (!group) {
    return res.status(404).json({ error: 'Group not found' });
  }

  if (!group.members.includes(req.session.username)) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }

  res.json(groupMessages[groupId] || []);
});

// ADMIN: GET /admin/users - list all users (admin only)
app.get('/admin/users', authMiddleware, (req, res) => {
  if (!req.session.isAdmin) {
    return res.status(403).json({ error: 'Admin only' });
  }

  const userList = Object.entries(users).map(([username, data]) => ({
    username,
    userId: data.userId,
    createdAt: data.createdAt
  }));

  res.json(userList);
});

// ADMIN: POST /admin/delete-user - delete any user (admin only)
app.post('/admin/delete-user', authMiddleware, (req, res) => {
  if (!req.session.isAdmin) {
    return res.status(403).json({ error: 'Admin only' });
  }

  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }

  if (!users[username]) {
    return res.status(404).json({ error: 'User not found' });
  }

  delete users[username];

  // Invalidate sessions for deleted user
  Object.keys(sessions).forEach(token => {
    if (sessions[token].username === username) {
      delete sessions[token];
    }
  });

  // Remove Firebase mirror
  removeFirebaseUser(username);

  res.json({ message: `User ${username} deleted by admin` });
});

// ADMIN: GET /admin/message-history - view all message history (admin only)
app.get('/admin/message-history', authMiddleware, (req, res) => {
  if (!req.session.isAdmin) {
    return res.status(403).json({ error: 'Admin only' });
  }

  res.json(messageHistory);
});

// ADMIN: GET /admin/group-history - view all group chat history (admin only)
app.get('/admin/group-history', authMiddleware, (req, res) => {
  if (!req.session.isAdmin) {
    return res.status(403).json({ error: 'Admin only' });
  }

  const allGroupData = Object.entries(groupMessages).map(([groupId, messages]) => ({
    groupId,
    groupInfo: groupChats[groupId],
    messages
  }));

  res.json(allGroupData);
});

app.get('/health', (req, res) => res.send('ok'));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Admin account: ${ADMIN_USERNAME} / password: jeremy0106`);
});