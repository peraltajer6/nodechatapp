// Firebase config - filled from Firebase Console for project chatapp2-f3777
const firebaseConfig = {
  apiKey: "AIzaSyDLtSSHrGHP5rSm_ugP27jXnn85PJXx_RA",
  authDomain: "chatapp2-f3777.firebaseapp.com",
  databaseURL: "https://chatapp2-f3777-default-rtdb.firebaseio.com",
  projectId: "chatapp2-f3777",
  storageBucket: "chatapp2-f3777.firebasestorage.app",
  messagingSenderId: "378117142942",
  appId: "1:378117142942:web:d0b6c61b496b70ff87fe8f"
};

// Initialize Firebase and database reference before using it
firebase.initializeApp(firebaseConfig);
const db = firebase.database();

// When the app loads, set up realtime user listeners
setupRealtimeUsers();

// State
let currentUser = null;
let currentToken = null;
let selectedUser = null;
let selectedGroup = null;
let allUsers = [];
let allGroups = [];
let messageListeners = {};
let groupMessageListeners = {};

// DOM Elements
const authScreen = document.getElementById('authScreen');
const chatScreen = document.getElementById('chatScreen');
const loginForm = document.getElementById('loginForm');
const signupForm = document.getElementById('signupForm');
const loginError = document.getElementById('loginError');
const signupError = document.getElementById('signupError');
const logoutBtn = document.getElementById('logoutBtn');
const deleteAcctBtn = document.getElementById('deleteAcctBtn');
const userSearch = document.getElementById('userSearch');
const usersList = document.getElementById('usersList');
const profileView = document.getElementById('profileView');
const chatView = document.getElementById('chatView');
const groupChatView = document.getElementById('groupChatView');
const messageForm = document.getElementById('messageForm');
const messageInput = document.getElementById('messageInput');
const messagesList = document.getElementById('messages');
const chatWith = document.getElementById('chatWith');
const groupsList = document.getElementById('groupsList');
const createGroupBtn = document.getElementById('createGroupBtn');
const createGroupModal = document.getElementById('createGroupModal');
const groupNameInput = document.getElementById('groupNameInput');
const confirmCreateGroupBtn = document.getElementById('confirmCreateGroupBtn');
const cancelCreateGroupBtn = document.getElementById('cancelCreateGroupBtn');
const groupMessageForm = document.getElementById('groupMessageForm');
const groupMessageInput = document.getElementById('groupMessageInput');
const groupMessages = document.getElementById('groupMessages');
const groupChatTitle = document.getElementById('groupChatTitle');
const panelTabs = document.querySelectorAll('.panel-tab-btn');
const panelContents = document.querySelectorAll('.panel-content');
const adminTabBtn = document.getElementById('adminTabBtn');
const adminPanel = document.getElementById('adminPanel');
const viewUsersBtn = document.getElementById('viewUsersBtn');
const viewGroupHistoryBtn = document.getElementById('viewGroupHistoryBtn');
const viewMsgHistoryBtn = document.getElementById('viewMsgHistoryBtn');
const adminView = document.getElementById('adminView');
const adminBackBtn = document.getElementById('adminBackBtn');

// Tab switching on login screen
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(tab + 'Form').classList.add('active');
  });
});

// Utility to switch panels (keeps behavior consistent even if admin tab is added/removed)
function switchToPanel(panelName) {
  document.querySelectorAll('.panel-tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.panel-content').forEach(c => c.classList.remove('active'));
  const btn = document.querySelector(`.panel-tab-btn[data-panel="${panelName}"]`);
  if (btn) btn.classList.add('active');
  const panel = document.getElementById(panelName + 'Panel');
  if (panel) panel.classList.add('active');
}

// Panel tabs (Users/Groups/Admin)
panelTabs.forEach(btn => {
  btn.addEventListener('click', () => switchToPanel(btn.dataset.panel));
});

// Login
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value.trim();

  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'Login failed');
    }

    const { token, userId, username: user, isAdmin } = await res.json();
    currentUser = { userId, username: user, isAdmin };
    currentToken = token;
    localStorage.setItem('token', token);
    localStorage.setItem('currentUser', JSON.stringify(currentUser));

    showChatScreen();
    if (isAdmin) {
      attachAdminPane();
    }
    loadUsers();
    loadGroups();
    messagesList.innerHTML = '';
    groupMessages.innerHTML = '';
  } catch (err) {
    loginError.textContent = err.message;
  }
});

// Signup
signupForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('signupUsername').value.trim();
  const password = document.getElementById('signupPassword').value.trim();
  const confirm = document.getElementById('signupConfirm').value.trim();

  if (password !== confirm) {
    signupError.textContent = 'Passwords do not match';
    return;
  }

  try {
    const res = await fetch('/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'Signup failed');
    }

    const { token, userId, username: user } = await res.json();
    currentUser = { userId, username: user, isAdmin: false };
    currentToken = token;
    localStorage.setItem('token', token);
    localStorage.setItem('currentUser', JSON.stringify(currentUser));

    showChatScreen();
    loadUsers();
    // write user to Firebase mirror so other clients see the new user instantly
    try {
      db.ref(`users/${user}`).set({ userId, username: user, createdAt: Date.now() });
    } catch (err) {
      console.error('Failed to write user to Firebase', err);
    }
    loadGroups();
  } catch (err) {
    signupError.textContent = err.message;
  }
});

// Manage admin pane visibility: attach or detach admin tab/panel depending on current user's admin status
function attachAdminPane() {
  try {
    const tabsContainer = document.querySelector('.panel-tabs');
    const contentsContainer = document.querySelector('.panel-contents');
    if (adminTabBtn && !document.getElementById('adminTabBtn')) {
      tabsContainer.appendChild(adminTabBtn);
      adminTabBtn.addEventListener('click', () => switchToPanel('admin'));
    }
    if (adminPanel && !document.getElementById('adminPanel')) {
      contentsContainer.appendChild(adminPanel);
    }
  } catch (err) {
    console.error('attachAdminPane error', err);
  }
}

function detachAdminPane() {
  try {
    if (adminTabBtn && adminTabBtn.parentNode) adminTabBtn.parentNode.removeChild(adminTabBtn);
    if (adminPanel && adminPanel.parentNode) adminPanel.parentNode.removeChild(adminPanel);
    // Ensure we switch back to users panel if admin was active
    switchToPanel('users');
  } catch (err) {
    console.error('detachAdminPane error', err);
  }
}

// Delete account
deleteAcctBtn.addEventListener('click', async () => {
  if (!confirm(`Delete account "${currentUser.username}"? This cannot be undone.`)) {
    return;
  }

  try {
    const res = await fetch('/delete-account', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentToken}`
      },
      body: JSON.stringify({ targetUsername: currentUser.username })
    });

    if (!res.ok) {
      throw new Error('Failed to delete account');
    }

    // Logout
    await fetch('/logout', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${currentToken}` }
    }).catch(() => {});

    currentUser = null;
    currentToken = null;
    localStorage.removeItem('token');
    localStorage.removeItem('currentUser');
    showAuthScreen();
  detachAdminPane();
    alert('Account deleted successfully');
  } catch (err) {
    alert('Error: ' + err.message);
  }
});

// Logout
logoutBtn.addEventListener('click', async () => {
  try {
    await fetch('/logout', {
      method: 'POST',
      headers: { Authorization: `Bearer ${currentToken}` }
    });
  } catch (err) {
    console.error('Logout error', err);
  }
  currentUser = null;
  currentToken = null;
  selectedUser = null;
  selectedGroup = null;
  localStorage.removeItem('token');
  localStorage.removeItem('currentUser');
  loginError.textContent = '';
  signupError.textContent = '';
  document.getElementById('loginUsername').value = '';
  document.getElementById('loginPassword').value = '';
  document.getElementById('signupUsername').value = '';
  document.getElementById('signupPassword').value = '';
  document.getElementById('signupConfirm').value = '';
  showAuthScreen();
  detachAdminPane();
});

// Load users from server
async function loadUsers() {
  try {
    const res = await fetch('/users');
    allUsers = await res.json();
    renderUserList(allUsers);
  } catch (err) {
    console.error('Load users error', err);
  }
}

// Realtime user listeners via Firebase
function setupRealtimeUsers() {
  const usersRef = db.ref('users');

  // existing users snapshot -> build list
  usersRef.once('value', snapshot => {
    const obj = snapshot.val() || {};
    allUsers = Object.values(obj).map(u => ({ username: u.username, userId: u.userId, createdAt: u.createdAt }));
    renderUserList(allUsers);
  });

  usersRef.on('child_added', snapshot => {
    const u = snapshot.val();
    // avoid duplicates
    if (!allUsers.some(x => x.username === u.username)) {
      allUsers.push({ username: u.username, userId: u.userId, createdAt: u.createdAt });
      renderUserList(allUsers);
    }
  });

  usersRef.on('child_removed', snapshot => {
    const u = snapshot.val();
    allUsers = allUsers.filter(x => x.username !== u.username);
    renderUserList(allUsers);
  });
}

// Render user list
function renderUserList(users) {
  usersList.innerHTML = '';
  users.forEach(user => {
    if (user.username === currentUser.username) return;
    const li = document.createElement('li');
    li.className = 'user-item';
    li.innerHTML = `<span>${escapeHtml(user.username)}</span>`;
    li.addEventListener('click', () => selectUser(user));
    usersList.appendChild(li);
  });
}

// Search users
userSearch.addEventListener('input', (e) => {
  const query = e.target.value.toLowerCase();
  const filtered = allUsers.filter(u => 
    u.username.toLowerCase().includes(query) && u.username !== currentUser.username
  );
  renderUserList(filtered);
});

// Select user and show profile
function selectUser(user) {
  selectedUser = user;
  selectedGroup = null;
  document.querySelectorAll('.user-item').forEach(li => li.classList.remove('active'));
  event.target.closest('.user-item').classList.add('active');
  showUserProfile(user);
}

// Show user profile
function showUserProfile(user) {
  profileView.style.display = 'block';
  chatView.style.display = 'none';
  groupChatView.style.display = 'none';
  adminView.style.display = 'none';
  profileView.innerHTML = `
    <div class="profile-card">
      <h2>${escapeHtml(user.username)}</h2>
      <p>User ID: <code>${user.userId}</code></p>
      <p>Joined: ${new Date(user.createdAt).toLocaleDateString()}</p>
      <button id="messagBtn" class="message-btn">Send Message</button>
    </div>
  `;
  document.getElementById('messagBtn').addEventListener('click', () => openChat(user));
}

// Open chat with user
function openChat(user) {
  selectedUser = user;
  selectedGroup = null;
  profileView.style.display = 'none';
  chatView.style.display = 'flex';
  groupChatView.style.display = 'none';
  adminView.style.display = 'none';
  chatWith.textContent = user.username;
  messagesList.innerHTML = '';

  const conversationKey = getConversationKey(currentUser.userId, user.userId);
  const messagesRef = db.ref(`messages/${conversationKey}`);
  
  // Clean up old listener
  if (messageListeners[conversationKey]) {
    messagesRef.off('child_added', messageListeners[conversationKey]);
  }

  // Set up new listener for real-time updates
  const listener = (snapshot) => {
    const msg = snapshot.val();
    addMessageToList(msg);
  };
  messageListeners[conversationKey] = listener;
  messagesRef.limitToLast(50).on('child_added', listener);

  messageForm.onsubmit = (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text) return;

    messagesRef.push({
      sender: currentUser.username,
      senderUserId: currentUser.userId,
      text,
      ts: Date.now()
    }).catch(err => console.error('Message send error', err));

    messageInput.value = '';
  };
}

// Get conversation key
function getConversationKey(userId1, userId2) {
  const ids = [userId1, userId2].sort();
  return ids.join('_');
}

// Add message to list
function addMessageToList(msg) {
  const li = document.createElement('li');
  const isOwn = msg.sender === currentUser.username;
  li.className = `message ${isOwn ? 'own' : 'other'}`;
  const time = new Date(msg.ts).toLocaleTimeString();
  li.innerHTML = `
    <div class="message-content">
      <span class="sender">${escapeHtml(msg.sender)}</span>
      <div class="text">${escapeHtml(msg.text)}</div>
      <small class="time">${time}</small>
    </div>
  `;
  messagesList.appendChild(li);
  messagesList.scrollTop = messagesList.scrollHeight;
}

// Load groups
async function loadGroups() {
  try {
    const res = await fetch('/groups', {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });
    if (res.ok) {
      allGroups = await res.json();
      renderGroupList();
    }
  } catch (err) {
    console.error('Load groups error', err);
  }
}

// Render groups list
function renderGroupList() {
  groupsList.innerHTML = '';
  allGroups.forEach(group => {
    const li = document.createElement('li');
    li.className = 'group-item';
    li.innerHTML = `
      <span class="group-item-title">${escapeHtml(group.name)}</span>
      <span class="group-item-members">${group.members.length} members</span>
    `;
    li.addEventListener('click', () => selectGroup(group));
    groupsList.appendChild(li);
  });
}

// Select group
function selectGroup(group) {
  selectedGroup = group;
  selectedUser = null;
  profileView.style.display = 'none';
  chatView.style.display = 'none';
  groupChatView.style.display = 'flex';
  adminView.style.display = 'none';
  openGroupChat(group);
}

// Open group chat
function openGroupChat(group) {
  groupChatTitle.textContent = group.name;
  groupMessages.innerHTML = '';

  // Load message history
  fetch(`/group/${group.groupId}/messages`, {
    headers: { 'Authorization': `Bearer ${currentToken}` }
  })
    .then(res => res.json())
    .then(msgs => {
      msgs.forEach(msg => addGroupMessageToList(msg));
      groupMessages.scrollTop = groupMessages.scrollHeight;
    })
    .catch(err => console.error('Load group messages error', err));

  groupMessageForm.onsubmit = (e) => {
    e.preventDefault();
    const text = groupMessageInput.value.trim();
    if (!text) return;

    fetch(`/group/${group.groupId}/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentToken}`
      },
      body: JSON.stringify({ text })
    })
      .then(() => {
        groupMessageInput.value = '';
      })
      .catch(err => console.error('Send group message error', err));
  };
}

// Add group message to list
function addGroupMessageToList(msg) {
  const li = document.createElement('li');
  const isOwn = msg.sender === currentUser.username;
  li.className = `message ${isOwn ? 'own' : 'other'}`;
  const time = new Date(msg.ts).toLocaleTimeString();
  li.innerHTML = `
    <div class="message-content">
      <span class="sender">${escapeHtml(msg.sender)}</span>
      <div class="text">${escapeHtml(msg.text)}</div>
      <small class="time">${time}</small>
    </div>
  `;
  groupMessages.appendChild(li);
  groupMessages.scrollTop = groupMessages.scrollHeight;
}

// Create group modal
createGroupBtn.addEventListener('click', () => {
  groupNameInput.value = '';
  const membersDiv = document.getElementById('groupMembersInput');
  membersDiv.innerHTML = '';
  allUsers.forEach(user => {
    if (user.username === currentUser.username) return;
    const label = document.createElement('label');
    label.innerHTML = `
      <input type="checkbox" value="${user.username}" />
      ${escapeHtml(user.username)}
    `;
    membersDiv.appendChild(label);
  });
  createGroupModal.style.display = 'flex';
});

confirmCreateGroupBtn.addEventListener('click', async () => {
  const groupName = groupNameInput.value.trim();
  if (!groupName) {
    alert('Group name required');
    return;
  }

  const memberCheckboxes = document.querySelectorAll('#groupMembersInput input[type="checkbox"]:checked');
  const memberUsernames = Array.from(memberCheckboxes).map(cb => cb.value);

  try {
    const res = await fetch('/group/create', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentToken}`
      },
      body: JSON.stringify({ groupName, memberUsernames })
    });

    if (res.ok) {
      createGroupModal.style.display = 'none';
      await loadGroups();
    }
  } catch (err) {
    alert('Error creating group: ' + err.message);
  }
});

cancelCreateGroupBtn.addEventListener('click', () => {
  createGroupModal.style.display = 'none';
});

// Admin functions
viewUsersBtn.addEventListener('click', async () => {
  try {
    const res = await fetch('/admin/users', {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });
    if (res.ok) {
      const users = await res.json();
      profileView.style.display = 'none';
      chatView.style.display = 'none';
      groupChatView.style.display = 'none';
      adminView.style.display = 'block';
      document.getElementById('adminViewContent').innerHTML = `
        <h3>All Users (${users.length})</h3>
        <div style="overflow-y: auto; max-height: 600px;">
          ${users.map(u => `
            <div style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
              <div><strong>${escapeHtml(u.username)}</strong></div>
              <div style="font-size: 12px; color: #6b7280;">ID: ${u.userId}</div>
              <div style="font-size: 12px; color: #6b7280;">Joined: ${new Date(u.createdAt).toLocaleDateString()}</div>
              <button onclick="deleteUserAdmin('${u.username}')" style="margin-top: 8px; padding: 6px 12px; background: #dc2626; color: white; border: none; border-radius: 4px; cursor: pointer;">Delete</button>
            </div>
          `).join('')}
        </div>
      `;
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
});

viewGroupHistoryBtn.addEventListener('click', async () => {
  try {
    const res = await fetch('/admin/group-history', {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });
    if (res.ok) {
      const history = await res.json();
      profileView.style.display = 'none';
      chatView.style.display = 'none';
      groupChatView.style.display = 'none';
      adminView.style.display = 'block';
      document.getElementById('adminViewContent').innerHTML = `
        <h3>Group Chat History</h3>
        <div style="overflow-y: auto; max-height: 600px;">
          ${history.map(h => `
            <div style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
              <div><strong>${escapeHtml(h.groupInfo?.name || 'Unknown')}</strong></div>
              <div style="font-size: 12px; color: #6b7280;">Members: ${h.groupInfo?.members?.join(', ') || 'N/A'}</div>
              <div style="font-size: 12px; color: #6b7280;">Messages: ${h.messages?.length || 0}</div>
              <div style="margin-top: 8px; background: #f3f4f6; padding: 8px; border-radius: 4px; font-size: 12px; max-height: 150px; overflow-y: auto;">
                ${(h.messages || []).map(m => `<div><strong>${m.sender}:</strong> ${escapeHtml(m.text)}</div>`).join('')}
              </div>
            </div>
          `).join('')}
        </div>
      `;
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
});

adminBackBtn.addEventListener('click', () => {
  adminView.style.display = 'none';
  profileView.style.display = 'block';
});

// Delete user as admin
async function deleteUserAdmin(username) {
  if (!confirm(`Delete user "${username}"?`)) return;
  try {
    const res = await fetch('/admin/delete-user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentToken}`
      },
      body: JSON.stringify({ username })
    });
    if (res.ok) {
      alert('User deleted');
      viewUsersBtn.click();
    }
  } catch (err) {
    alert('Error: ' + err.message);
  }
}

function escapeHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function showAuthScreen() {
  authScreen.classList.add('active');
  chatScreen.classList.remove('active');
}

function showChatScreen() {
  authScreen.classList.remove('active');
  chatScreen.classList.add('active');
}

// Check if already logged in
window.addEventListener('load', () => {
  const saved = localStorage.getItem('currentUser');
  const token = localStorage.getItem('token');
  if (saved && token) {
    currentUser = JSON.parse(saved);
    currentToken = token;
    showChatScreen();
    if (currentUser.isAdmin) {
      attachAdminPane();
    } else {
      detachAdminPane();
    }
    loadUsers();
    loadGroups();
  } else {
    showAuthScreen();
  }
});

// Ensure admin pane hidden by default for non-admins
if (!localStorage.getItem('currentUser')) {
  // On initial load when no one is logged in, remove the admin pane from the DOM
  detachAdminPane();
}
