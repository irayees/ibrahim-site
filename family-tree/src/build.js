const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');
const subtle = globalThis.crypto?.subtle || webcrypto.subtle;

const envPath = path.join(__dirname, "..", ".env");
if (fs.existsSync(envPath)) {
  if (typeof process.loadEnvFile === "function") {
    process.loadEnvFile(envPath);
  } else {
    for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
      const m = line.match(/^\s*([^#=]+?)\s*=\s*(.*)\s*$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
    }
  }
}

const VIEWER_PASSWORD = process.env.VIEWER_PASSWORD;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const GITHUB_PAT = process.env.GITHUB_PAT;
if (!VIEWER_PASSWORD || !ADMIN_PASSWORD || !GITHUB_PAT) {
  throw new Error("Missing VIEWER_PASSWORD, ADMIN_PASSWORD, or GITHUB_PAT in family-tree/.env");
}
const ITERATIONS = 250000;

function toBase64(buf) {
  return Buffer.from(buf).toString('base64');
}

async function deriveKey(password, salt) {
  const keyMaterial = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptText(plaintext, password, salt) {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const cipher = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  return { iv: toBase64(iv), data: toBase64(cipher) };
}

(async () => {
  if (!GITHUB_PAT || GITHUB_PAT === 'PASTE_YOUR_GITHUB_PAT_HERE') {
    console.error('ERROR: Please replace PASTE_YOUR_GITHUB_PAT_HERE in src/build.js with your GitHub token first.');
    process.exit(1);
  }

  const appHtmlPath = path.join(__dirname, 'app.html');
  const outHtmlPath = path.join(__dirname, '..', 'index.html');
  const appHtml = fs.readFileSync(appHtmlPath, 'utf8');

  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const appEnc = await encryptText(appHtml, VIEWER_PASSWORD, salt);
  const adminEnv = await encryptText(VIEWER_PASSWORD, ADMIN_PASSWORD, salt);
  const patEnc = await encryptText(GITHUB_PAT.trim(), ADMIN_PASSWORD, salt);

  const vault = {
    v: 2,
    iter: ITERATIONS,
    salt: toBase64(salt),
    appIv: appEnc.iv,
    appData: appEnc.data,
    envIv: adminEnv.iv,
    envData: adminEnv.data,
    patIv: patEnc.iv,
    patData: patEnc.data
  };

  const outerHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Family Tree</title>
  <style>
    :root {
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-alt: #f1f5f9;
      --border: #e2e8f0;
      --border-strong: #cbd5e1;
      --text: #0f172a;
      --muted: #64748b;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --accent-ring: rgba(37, 99, 235, 0.25);
      --danger: #dc2626;
      --danger-bg: #fef2f2;
      --danger-border: #fecaca;
      --shadow-lg: 0 16px 40px rgba(15, 23, 42, 0.16);
    }
    * { box-sizing: border-box; }
    [hidden] { display: none !important; }
    html, body {
      margin: 0;
      padding: 0;
      height: 100%;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      -webkit-font-smoothing: antialiased;
    }
    #lockscreen {
      position: fixed;
      inset: 0;
      z-index: 9999;
      background: radial-gradient(circle at top, #eff6ff 0%, #f8fafc 65%);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .lock-card {
      width: 100%;
      max-width: 390px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: var(--shadow-lg);
      padding: 28px 26px 24px;
      text-align: center;
    }
    .lock-icon {
      width: 48px;
      height: 48px;
      margin: 0 auto 14px;
      border-radius: 12px;
      background: #eff6ff;
      border: 1px solid #bfdbfe;
      color: var(--accent);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.35rem;
    }
    .lock-card h1 {
      margin: 0 0 6px;
      font-size: 1.3rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .lock-card p {
      margin: 0 0 20px;
      font-size: 0.88rem;
      color: var(--muted);
      line-height: 1.45;
    }
    .lock-form {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .pw-wrap {
      position: relative;
      display: flex;
      align-items: center;
    }
    .pw-wrap input {
      width: 100%;
      padding: 10px 64px 10px 13px;
      font-size: 0.95rem;
      border: 1px solid var(--border-strong);
      border-radius: 10px;
      background: var(--surface);
      color: var(--text);
      outline: none;
      transition: border-color 0.15s, box-shadow 0.15s;
    }
    .pw-wrap input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-ring);
    }
    .pw-toggle {
      position: absolute;
      right: 8px;
      appearance: none;
      border: none;
      background: transparent;
      color: var(--muted);
      font-size: 0.78rem;
      font-weight: 600;
      padding: 4px 8px;
      border-radius: 6px;
      cursor: pointer;
    }
    .pw-toggle:hover {
      background: var(--surface-alt);
      color: var(--text);
    }
    .btn-primary {
      appearance: none;
      background: var(--accent);
      color: #ffffff;
      border: 1px solid var(--accent);
      border-radius: 10px;
      padding: 10px 16px;
      font-size: 0.92rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s, transform 0.05s;
    }
    .btn-primary:hover { background: var(--accent-hover); }
    .btn-primary:active { transform: translateY(1px); }
    .btn-primary:disabled { opacity: 0.65; cursor: not-allowed; }
    .lock-err {
      margin-top: 4px;
      padding: 8px 10px;
      border-radius: 8px;
      background: var(--danger-bg);
      border: 1px solid var(--danger-border);
      color: var(--danger);
      font-size: 0.82rem;
      font-weight: 600;
    }
    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-6px); }
      40%, 80% { transform: translateX(6px); }
    }
    .shake { animation: shake 0.32s ease-in-out; }
  </style>
</head>
<body>

<div id="lockscreen" role="dialog" aria-modal="true" aria-labelledby="lock-title">
  <div class="lock-card" id="lock-card">
    <div class="lock-icon" aria-hidden="true">🔒</div>
    <h1 id="lock-title">Family Tree</h1>
    <p>This family tree is password protected. Enter the password to view.</p>
    <form class="lock-form" id="lock-form">
      <div class="pw-wrap">
        <input
          id="pw-input"
          type="password"
          placeholder="Enter password"
          aria-label="Password"
          autocomplete="current-password"
          required
          autofocus
        />
        <button type="button" class="pw-toggle" id="pw-toggle" aria-label="Show password">Show</button>
      </div>
      <button type="submit" class="btn-primary" id="unlock-btn">Unlock Family Tree</button>
      <div class="lock-err" id="lock-err" hidden>Incorrect password. Please try again.</div>
    </form>
  </div>
</div>

<div id="app-mount"></div>

<script id="vault-data" type="application/json">${JSON.stringify(vault)}</script>

<script>
(() => {
  const SESSION_HTML_KEY = 'ft_session_html_v2';
  const SESSION_ADMIN_KEY = 'ft_session_admin_v2';
  const SESSION_PAT_KEY = 'ft_session_pat_v2';
  const SESSION_VPW_KEY = 'ft_session_vpw_v2';
  const SESSION_APW_KEY = 'ft_session_apw_v2';

  const lockscreenEl = document.getElementById('lockscreen');
  const lockCardEl = document.getElementById('lock-card');
  const lockFormEl = document.getElementById('lock-form');
  const pwInputEl = document.getElementById('pw-input');
  const pwToggleEl = document.getElementById('pw-toggle');
  const lockErrEl = document.getElementById('lock-err');
  const unlockBtn = document.getElementById('unlock-btn');
  const appMountEl = document.getElementById('app-mount');

  function fromBase64(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function toBase64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  async function deriveKey(password, salt, iterations) {
    const mat = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      mat,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function decryptString(b64Data, b64Iv, password, salt, iterations) {
    const key = await deriveKey(password, salt, iterations);
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(b64Iv) },
      key,
      fromBase64(b64Data)
    );
    return new TextDecoder().decode(plainBuf);
  }

  async function encryptString(plaintext, password, salt, iterations) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, iterations);
    const cipherBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    return { iv: toBase64(iv), data: toBase64(cipherBuf) };
  }

  window.__FT_BUILD_ENCRYPTED_HTML__ = async function(updatedAppHtml, viewerPw, adminPw, ghPat) {
    const iterations = 250000;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const appEnc = await encryptString(updatedAppHtml, viewerPw, salt, iterations);
    const adminEnv = await encryptString(viewerPw, adminPw, salt, iterations);
    const patEnc = await encryptString(ghPat, adminPw, salt, iterations);

    const newVault = {
      v: 2,
      iter: iterations,
      salt: toBase64(salt),
      appIv: appEnc.iv,
      appData: appEnc.data,
      envIv: adminEnv.iv,
      envData: adminEnv.data,
      patIv: patEnc.iv,
      patData: patEnc.data
    };

    const clone = document.documentElement.cloneNode(true);
    clone.querySelector('title').textContent = 'Family Tree';
    clone.querySelectorAll('[data-app-style]').forEach(el => el.remove());
    clone.querySelector('#app-mount').innerHTML = '';
    const ls = clone.querySelector('#lockscreen');
    ls.removeAttribute('hidden');
    const err = clone.querySelector('#lock-err');
    err.setAttribute('hidden', '');
    const inp = clone.querySelector('#pw-input');
    inp.value = '';
    inp.setAttribute('type', 'password');
    clone.querySelector('#pw-toggle').textContent = 'Show';
    clone.querySelector('#vault-data').textContent = JSON.stringify(newVault);

    return '<!DOCTYPE html>\\n' + clone.outerHTML;
  };

  window.__FT_LOCK_APP__ = function() {
    sessionStorage.removeItem(SESSION_HTML_KEY);
    sessionStorage.removeItem(SESSION_ADMIN_KEY);
    sessionStorage.removeItem(SESSION_PAT_KEY);
    sessionStorage.removeItem(SESSION_VPW_KEY);
    sessionStorage.removeItem(SESSION_APW_KEY);
    window.__FT_GH_PAT__ = '';
    window.__FT_VIEWER_PW__ = '';
    window.__FT_ADMIN_PW__ = '';
    document.querySelectorAll('[data-app-style]').forEach(el => el.remove());
    appMountEl.innerHTML = '';
    document.title = 'Family Tree';
    lockscreenEl.hidden = false;
    lockErrEl.hidden = true;
    pwInputEl.value = '';
    setTimeout(() => pwInputEl.focus(), 50);
  };

  function mountApp(rawAppHtml, isAdmin) {
    window.__FT_RAW_APP_HTML__ = rawAppHtml;
    window.__FT_IS_ADMIN__ = isAdmin;

    sessionStorage.setItem(SESSION_HTML_KEY, rawAppHtml);
    sessionStorage.setItem(SESSION_ADMIN_KEY, isAdmin ? '1' : '0');

    const doc = new DOMParser().parseFromString(rawAppHtml, 'text/html');
    document.title = doc.title || 'Family Tree';

    document.querySelectorAll('[data-app-style]').forEach(el => el.remove());
    doc.querySelectorAll('head style').forEach(st => {
      const styleEl = document.createElement('style');
      styleEl.setAttribute('data-app-style', '1');
      styleEl.textContent = st.textContent;
      document.head.appendChild(styleEl);
    });

    appMountEl.innerHTML = '';
    const scripts = [];
    Array.from(doc.body.childNodes).forEach(node => {
      if (node.nodeName === 'SCRIPT') {
        scripts.push(node);
      } else {
        appMountEl.appendChild(document.importNode(node, true));
      }
    });

    lockscreenEl.hidden = true;
    lockErrEl.hidden = true;
    pwInputEl.value = '';

    for (const oldScript of scripts) {
      const newScript = document.createElement('script');
      if (oldScript.id) newScript.id = oldScript.id;
      if (oldScript.type) newScript.type = oldScript.type;
      newScript.textContent = oldScript.textContent;
      appMountEl.appendChild(newScript);
    }
  }

  pwToggleEl.addEventListener('click', () => {
    const isPw = pwInputEl.type === 'password';
    pwInputEl.type = isPw ? 'text' : 'password';
    pwToggleEl.textContent = isPw ? 'Hide' : 'Show';
    pwToggleEl.setAttribute('aria-label', isPw ? 'Hide password' : 'Show password');
    pwInputEl.focus();
  });

  lockFormEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const entered = pwInputEl.value.trim();
    if (!entered) return;

    unlockBtn.disabled = true;
    unlockBtn.textContent = 'Unlocking…';

    try {
      const vault = JSON.parse(document.getElementById('vault-data').textContent);
      const salt = fromBase64(vault.salt);

      // 1. Try Viewer password ("memon")
      try {
        const html = await decryptString(vault.appData, vault.appIv, entered, salt, vault.iter);
        mountApp(html, false);
        return;
      } catch (_) {}

      // 2. Try Admin password ("AsSabiqoon2643")
      try {
        const viewerPw = await decryptString(vault.envData, vault.envIv, entered, salt, vault.iter);
        const html = await decryptString(vault.appData, vault.appIv, viewerPw, salt, vault.iter);
        const ghPat = vault.patData
          ? await decryptString(vault.patData, vault.patIv, entered, salt, vault.iter)
          : '';
        window.__FT_VIEWER_PW__ = viewerPw;
        window.__FT_ADMIN_PW__ = entered;
        window.__FT_GH_PAT__ = ghPat;
        sessionStorage.setItem(SESSION_VPW_KEY, viewerPw);
        sessionStorage.setItem(SESSION_APW_KEY, entered);
        sessionStorage.setItem(SESSION_PAT_KEY, ghPat);
        mountApp(html, true);
        return;
      } catch (_) {}

      // 3. Invalid password
      lockErrEl.hidden = false;
      lockCardEl.classList.remove('shake');
      void lockCardEl.offsetWidth;
      lockCardEl.classList.add('shake');
      pwInputEl.select();
    } finally {
      unlockBtn.disabled = false;
      unlockBtn.textContent = 'Unlock Family Tree';
    }
  });

  const cachedHtml = sessionStorage.getItem(SESSION_HTML_KEY);
  if (cachedHtml) {
    const isAdmin = sessionStorage.getItem(SESSION_ADMIN_KEY) === '1';
    if (isAdmin) {
      window.__FT_VIEWER_PW__ = sessionStorage.getItem(SESSION_VPW_KEY) || '';
      window.__FT_ADMIN_PW__ = sessionStorage.getItem(SESSION_APW_KEY) || '';
      window.__FT_GH_PAT__ = sessionStorage.getItem(SESSION_PAT_KEY) || '';
    }
    mountApp(cachedHtml, isAdmin);
  }
})();
</script>
</body>
</html>`;

  fs.writeFileSync(outHtmlPath, outerHtml, 'utf8');
  console.log('Successfully generated encrypted index.html with embedded encrypted PAT');
})();