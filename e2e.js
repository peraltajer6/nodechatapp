const puppeteer = require('puppeteer');

(async () => {
  const BASE = 'http://localhost:3000';
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'], defaultViewport: { width: 1200, height: 800 } });
  try {
    const pageA = await browser.newPage();
    const pageB = await browser.newPage();

    // Helper to sign up a user via the UI
    async function signup(page, username) {
      await page.goto(BASE, { waitUntil: 'networkidle2' });
      // Click signup tab
      await page.click('.tab-btn[data-tab="signup"]');
      await page.waitForSelector('#signupForm');
      await page.type('#signupUsername', username);
      await page.type('#signupPassword', 'test123');
      await page.type('#signupConfirm', 'test123');
      await page.click('#signupForm button[type="submit"]');
      // Wait for chat screen
      await page.waitForSelector('.chat-container', { timeout: 5000 });
    }

    // Sign up two users
    const user1 = 'e2e_user1';
    const user2 = 'e2e_user2';
    await signup(pageA, user1);
    await signup(pageB, user2);

    // Wait for user lists to populate and for each page to see the other user
    await pageA.waitForSelector('#usersList', { timeout: 10000 });
    await pageB.waitForSelector('#usersList', { timeout: 10000 });

    // Wait until pageA sees user2 in the list
    await pageA.waitForFunction((u) => {
      const items = Array.from(document.querySelectorAll('#usersList .user-item'));
      return items.some(li => li.textContent.trim().toLowerCase() === u.toLowerCase());
    }, { timeout: 10000 }, user2);

    // Wait until pageB sees user1 in the list
    await pageB.waitForFunction((u) => {
      const items = Array.from(document.querySelectorAll('#usersList .user-item'));
      return items.some(li => li.textContent.trim().toLowerCase() === u.toLowerCase());
    }, { timeout: 10000 }, user1);

    // On pageA, click the user in the list matching user2
    await pageA.evaluate((u) => {
      const items = Array.from(document.querySelectorAll('#usersList .user-item'));
      const found = items.find(li => li.textContent.trim().toLowerCase() === u.toLowerCase());
      if (found) found.click();
    }, user2);

    // Wait for chat view to appear and message input
    await pageA.waitForSelector('#messageInput');

    // Send a message from A to B
    const messageText = 'Hello from A ' + Date.now();
    await pageA.type('#messageInput', messageText);
    await pageA.click('#messageForm button[type="submit"]');

    // Wait until message appears in pageB messages list (give up to 8s)
    await pageB.waitForFunction((msg) => {
      const lis = Array.from(document.querySelectorAll('#messages li'));
      return lis.some(li => li.innerText.includes(msg));
    }, { timeout: 8000 }, messageText);

    const found = true;

    if (!found) {
      console.error('E2E FAILED: message not found in pageB');
      process.exitCode = 2;
    } else {
      console.log('E2E OK: message delivered and observed in pageB');
    }

    // Cleanup: try to delete test users via API
    const tokenA = await pageA.evaluate(() => localStorage.getItem('token'));
    if (tokenA) {
      await pageA.evaluate(async (t, u) => {
        await fetch('/delete-account', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${t}` }, body: JSON.stringify({ targetUsername: u }) });
      }, tokenA, user1);
    }
    const tokenB = await pageB.evaluate(() => localStorage.getItem('token'));
    if (tokenB) {
      await pageB.evaluate(async (t, u) => {
        await fetch('/delete-account', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${t}` }, body: JSON.stringify({ targetUsername: u }) });
      }, tokenB, user2);
    }

    await browser.close();
  } catch (err) {
    console.error('E2E error', err);
    try { await browser.close(); } catch (e) {}
    process.exitCode = 1;
  }
})();
