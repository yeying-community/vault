const $ = (id) => document.getElementById(id);

const capabilityText = $('capability-text');
const setupSection = $('setup-section');
const unlockSection = $('unlock-section');
const vaultSection = $('vault-section');
const statusText = $('status-text');

const registerBtn = $('register-btn');
const unlockBtn = $('unlock-btn');
const lockBtn = $('lock-btn');
const syncTimeBtn = $('sync-time-btn');

const addForm = $('add-form');
const issuerInput = $('issuer-input');
const accountInput = $('account-input');
const secretInput = $('secret-input');
const digitsInput = $('digits-input');
const periodInput = $('period-input');

const tokenList = $('token-list');

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  unlocked: false,
  vault: null,
  key: null,
  timeSkewMs: 0,
  prfSupported: null,
  prfSalt: null,
  ticker: null,
  updateInFlight: false,
};

init();

async function init() {
  registerBtn.addEventListener('click', onRegister);
  unlockBtn.addEventListener('click', onUnlock);
  lockBtn.addEventListener('click', onLock);
  syncTimeBtn.addEventListener('click', syncTime);
  addForm.addEventListener('submit', onAddToken);

  await detectCapabilities();
}

async function detectCapabilities() {
  if (!window.isSecureContext) {
    capabilityText.textContent = '需要安全上下文（HTTPS 或 localhost）才能使用 WebAuthn。';
    setStatus('当前不是安全上下文。请使用 HTTPS 或 localhost。', true);
    return;
  }

  if (!('PublicKeyCredential' in window)) {
    capabilityText.textContent = '当前浏览器不支持 WebAuthn。';
    setStatus('浏览器不支持 WebAuthn。', true);
    return;
  }

  let platformAvailable = false;
  try {
    platformAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch (err) {
    platformAvailable = false;
  }

  capabilityText.textContent = platformAvailable
    ? '支持 WebAuthn 与平台认证器（指纹/人脸）。'
    : '浏览器支持 WebAuthn，但没有可用的平台认证器。';

  if (!platformAvailable) {
    setStatus('未检测到可用的设备认证器。请使用带生物识别的设备。', true);
    return;
  }

  try {
    const status = await api('/api/webauthn/status');
    if (status.registered) {
      unlockSection.hidden = false;
    } else {
      setupSection.hidden = false;
    }
    setStatus('准备就绪');
  } catch (err) {
    setStatus('无法连接服务器。', true);
  }
}

async function onRegister() {
  setStatus('正在创建 Passkey...');
  registerBtn.disabled = true;
  try {
    const options = await api('/api/webauthn/register/options', { method: 'POST', body: { force: false } });
    const publicKey = normalizeRegistrationOptions(options);
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) {
      throw new Error('创建 Passkey 失败。');
    }
    const attestation = credentialToJSON(credential);
    await api('/api/webauthn/register/verify', { method: 'POST', body: attestation });

    setupSection.hidden = true;
    unlockSection.hidden = false;
    setStatus('Passkey 创建完成。');
  } catch (err) {
    setStatus(err?.message || 'Passkey 创建失败。', true);
  } finally {
    registerBtn.disabled = false;
  }
}

async function onUnlock() {
  setStatus('正在解锁 Vault...');
  unlockBtn.disabled = true;
  try {
    const options = await api('/api/webauthn/authenticate/options', { method: 'POST' });
    if (!options.prfSalt) {
      throw new Error('服务器缺少 PRF Salt。');
    }
    state.prfSalt = options.prfSalt;
    const publicKey = normalizeAuthenticationOptions(options);
    publicKey.extensions = {
      prf: {
        eval: {
          first: coerceToBytes(options.prfSalt, 'prfSalt'),
        },
      },
    };

    const assertion = await navigator.credentials.get({ publicKey });
    if (!assertion) {
      throw new Error('认证失败。');
    }

    const clientExtensions = assertion.getClientExtensionResults?.() || {};
    const prfOutput = extractPrfOutput(clientExtensions);
    if (!prfOutput) {
      state.prfSupported = false;
      throw new Error('当前设备不支持 PRF 扩展，无法安全解密 Vault。');
    }
    state.prfSupported = true;

    const assertionJson = credentialToJSON(assertion);
    await api('/api/webauthn/authenticate/verify', { method: 'POST', body: assertionJson });

    state.key = await deriveAesKey(prfOutput);
    const vault = await loadVault(state.key);

    state.vault = vault || createEmptyVault();
    state.unlocked = true;
    unlockSection.hidden = true;
    vaultSection.hidden = false;
    lockBtn.disabled = false;

    renderTokens();
    startTicker();
    setStatus('Vault 已解锁。');
  } catch (err) {
    setStatus(err?.message || '解锁失败。', true);
  } finally {
    unlockBtn.disabled = false;
  }
}

function onLock() {
  state.unlocked = false;
  state.vault = null;
  state.key = null;
  stopTicker();
  vaultSection.hidden = true;
  unlockSection.hidden = false;
  lockBtn.disabled = true;
  tokenList.innerHTML = '';
  setStatus('Vault 已锁定。');
}

async function onAddToken(event) {
  event.preventDefault();
  if (!state.unlocked || !state.key) {
    setStatus('Vault 未解锁。', true);
    return;
  }

  const inputValue = secretInput.value.trim();
  if (!inputValue) {
    setStatus('请输入 Secret 或 otpauth URL。', true);
    return;
  }

  try {
    const parsed = parseSecretInput(inputValue);
    const issuer = issuerInput.value.trim() || parsed.issuer || 'Unknown';
    const account = accountInput.value.trim() || parsed.account || 'Unknown';
    const digits = Number(parsed.digits || digitsInput.value || 6);
    const period = Number(parsed.period || periodInput.value || 30);

    const token = {
      id: crypto.randomUUID(),
      issuer,
      account,
      secret: parsed.secret,
      digits,
      period,
      algorithm: parsed.algorithm || 'SHA-1',
      createdAt: Date.now(),
    };
    token._secretBytes = base32ToBytes(token.secret);

    state.vault.tokens.push(token);
    await persistVault();

    issuerInput.value = '';
    accountInput.value = '';
    secretInput.value = '';

    renderTokens();
    setStatus('已添加账号。');
  } catch (err) {
    setStatus(err?.message || '无法解析 Secret。', true);
  }
}

async function persistVault() {
  if (!state.key || !state.vault) {
    return;
  }
  const payload = normalizeVaultForStorage(state.vault);
  const encrypted = await encryptVault(state.key, payload);
  await saveEncryptedVault(encrypted);
}

function renderTokens() {
  tokenList.innerHTML = '';
  if (!state.vault || state.vault.tokens.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = '尚未添加账号。';
    tokenList.appendChild(empty);
    return;
  }

  for (const token of state.vault.tokens) {
    const card = document.createElement('div');
    card.className = 'token';
    card.dataset.tokenId = token.id;

    const main = document.createElement('div');
    main.className = 'token-main';

    const label = document.createElement('div');
    label.className = 'token-label';
    const issuer = document.createElement('div');
    issuer.className = 'issuer';
    issuer.textContent = token.issuer;
    const account = document.createElement('div');
    account.className = 'account';
    account.textContent = token.account;
    label.appendChild(issuer);
    label.appendChild(account);

    const codeWrap = document.createElement('div');
    codeWrap.className = 'code';
    const digits = document.createElement('div');
    digits.className = 'digits';
    digits.textContent = '------';
    const copyBtn = document.createElement('button');
    copyBtn.className = 'ghost';
    copyBtn.type = 'button';
    copyBtn.textContent = '复制';
    copyBtn.addEventListener('click', () => copyCode(token.id));
    codeWrap.appendChild(digits);
    codeWrap.appendChild(copyBtn);

    main.appendChild(label);
    main.appendChild(codeWrap);

    const timer = document.createElement('div');
    timer.className = 'timer';
    const bar = document.createElement('div');
    bar.className = 'bar';
    const remaining = document.createElement('div');
    remaining.className = 'remaining';
    remaining.textContent = '--s';
    timer.appendChild(bar);
    timer.appendChild(remaining);

    const footer = document.createElement('div');
    footer.className = 'actions';
    const removeBtn = document.createElement('button');
    removeBtn.className = 'ghost';
    removeBtn.type = 'button';
    removeBtn.textContent = '删除';
    removeBtn.addEventListener('click', () => removeToken(token.id));
    footer.appendChild(removeBtn);

    card.appendChild(main);
    card.appendChild(timer);
    card.appendChild(footer);

    tokenList.appendChild(card);
  }
}

async function removeToken(id) {
  if (!state.vault) {
    return;
  }
  state.vault.tokens = state.vault.tokens.filter((token) => token.id !== id);
  await persistVault();
  renderTokens();
  setStatus('已删除账号。');
}

function startTicker() {
  stopTicker();
  state.ticker = setInterval(updateTokenDisplay, 1000);
  updateTokenDisplay();
}

function stopTicker() {
  if (state.ticker) {
    clearInterval(state.ticker);
    state.ticker = null;
  }
}

async function updateTokenDisplay() {
  if (!state.vault || !state.unlocked) {
    return;
  }
  if (state.updateInFlight) {
    return;
  }
  state.updateInFlight = true;
  try {
    const now = Date.now() + state.timeSkewMs;
    const tokens = state.vault.tokens;
    for (const token of tokens) {
      if (!token._secretBytes) {
        token._secretBytes = base32ToBytes(token.secret);
      }
    }

    const cards = Array.from(tokenList.querySelectorAll('.token'));
    await Promise.all(
      cards.map(async (card) => {
        const token = tokens.find((item) => item.id === card.dataset.tokenId);
        if (!token) {
          return;
        }
        const digitsEl = card.querySelector('.digits');
        const remainingEl = card.querySelector('.remaining');
        const barEl = card.querySelector('.bar');

        const code = await generateTotp(token._secretBytes, token.period, token.digits, token.algorithm, now);
        if (digitsEl) {
          digitsEl.textContent = code;
        }
        const remaining = token.period - (Math.floor(now / 1000) % token.period);
        if (remainingEl) {
          remainingEl.textContent = `${remaining}s`;
        }
        if (barEl) {
          const progress = (token.period - remaining) / token.period;
          barEl.style.setProperty('--progress', Math.max(0, Math.min(1, progress)).toString());
        }
      }),
    );
  } catch (err) {
    setStatus('更新验证码失败。', true);
  } finally {
    state.updateInFlight = false;
  }
}

async function copyCode(id) {
  const token = state.vault?.tokens.find((item) => item.id === id);
  if (!token) {
    return;
  }
  if (!token._secretBytes) {
    token._secretBytes = base32ToBytes(token.secret);
  }
  const now = Date.now() + state.timeSkewMs;
  const code = await generateTotp(token._secretBytes, token.period, token.digits, token.algorithm, now);
  try {
    await navigator.clipboard.writeText(code);
    setStatus('已复制验证码。');
  } catch (err) {
    setStatus('复制失败，请手动复制。', true);
  }
}

async function syncTime() {
  try {
    const { now } = await api('/api/time');
    state.timeSkewMs = now - Date.now();
    setStatus('时间已校准。');
  } catch (err) {
    setStatus('时间校准失败。', true);
  }
}

function setStatus(message, isError = false) {
  statusText.textContent = message;
  statusText.classList.toggle('error', isError);
}

function normalizeRegistrationOptions(options) {
  return {
    ...options,
    challenge: coerceToBytes(options.challenge, 'challenge'),
    user: {
      ...options.user,
      id: coerceToBytes(options?.user?.id, 'user.id'),
    },
    excludeCredentials: (options.excludeCredentials || []).map((cred) => ({
      ...cred,
      id: coerceToBytes(cred.id, 'excludeCredentials.id'),
    })),
  };
}

function normalizeAuthenticationOptions(options) {
  return {
    ...options,
    challenge: coerceToBytes(options.challenge, 'challenge'),
    allowCredentials: (options.allowCredentials || []).map((cred) => ({
      ...cred,
      id: coerceToBytes(cred.id, 'allowCredentials.id'),
    })),
  };
}

function credentialToJSON(credential) {
  if (!credential) {
    return null;
  }
  const response = credential.response;
  const clientExtensionResults = credential.getClientExtensionResults?.() || {};
  const json = {
    id: credential.id,
    rawId: bytesToBase64url(new Uint8Array(credential.rawId)),
    type: credential.type,
    clientExtensionResults,
    response: {
      clientDataJSON: bytesToBase64url(new Uint8Array(response.clientDataJSON)),
    },
  };
  if (response.attestationObject) {
    json.response.attestationObject = bytesToBase64url(new Uint8Array(response.attestationObject));
  }
  if (response.authenticatorData) {
    json.response.authenticatorData = bytesToBase64url(new Uint8Array(response.authenticatorData));
  }
  if (response.signature) {
    json.response.signature = bytesToBase64url(new Uint8Array(response.signature));
  }
  if (response.userHandle) {
    json.response.userHandle = bytesToBase64url(new Uint8Array(response.userHandle));
  }
  if (response.getTransports) {
    json.response.transports = response.getTransports();
  }
  return json;
}

function extractPrfOutput(clientExtensions) {
  const prf = clientExtensions?.prf;
  if (!prf) {
    return null;
  }
  if (prf.results?.first) {
    return new Uint8Array(prf.results.first);
  }
  if (prf.first) {
    return new Uint8Array(prf.first);
  }
  return null;
}

async function deriveAesKey(prfOutput) {
  const keyMaterial = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encoder.encode('vault-key'),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function createEmptyVault() {
  return {
    version: 1,
    updatedAt: Date.now(),
    tokens: [],
  };
}

function normalizeVaultForStorage(vault) {
  return {
    version: vault.version,
    updatedAt: Date.now(),
    tokens: vault.tokens.map((token) => ({
      id: token.id,
      issuer: token.issuer,
      account: token.account,
      secret: token.secret,
      digits: token.digits,
      period: token.period,
      algorithm: token.algorithm,
      createdAt: token.createdAt,
    })),
  };
}

async function encryptVault(key, vault) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = encoder.encode(JSON.stringify(vault));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return {
    id: 'main',
    iv: bytesToBase64url(iv),
    data: bytesToBase64url(new Uint8Array(encrypted)),
    updatedAt: Date.now(),
  };
}

async function loadVault(key) {
  const encrypted = await loadEncryptedVault();
  if (!encrypted) {
    return null;
  }
  const iv = base64urlToBytes(encrypted.iv);
  const data = base64urlToBytes(encrypted.data);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  const vault = JSON.parse(decoder.decode(decrypted));
  return vault;
}

async function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('web-authenticator', 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('vault')) {
        db.createObjectStore('vault', { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function loadEncryptedVault() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('vault', 'readonly');
    const store = tx.objectStore('vault');
    const request = store.get('main');
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

async function saveEncryptedVault(record) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('vault', 'readwrite');
    const store = tx.objectStore('vault');
    store.put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function parseSecretInput(input) {
  if (input.startsWith('otpauth://')) {
    const url = new URL(input);
    const type = url.host;
    if (type !== 'totp') {
      throw new Error('仅支持 TOTP。');
    }
    const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
    let issuer = url.searchParams.get('issuer') || '';
    let account = '';
    if (label.includes(':')) {
      const parts = label.split(':');
      issuer = issuer || parts[0];
      account = parts.slice(1).join(':');
    } else {
      account = label;
    }

    const secret = url.searchParams.get('secret');
    if (!secret) {
      throw new Error('otpauth URL 缺少 secret。');
    }
    const digits = url.searchParams.get('digits');
    const period = url.searchParams.get('period');
    const algorithmRaw = url.searchParams.get('algorithm');
    const algorithm = normalizeAlgorithm(algorithmRaw || 'SHA1');

    return {
      issuer,
      account,
      secret,
      digits: digits ? Number(digits) : null,
      period: period ? Number(period) : null,
      algorithm,
    };
  }

  return {
    issuer: '',
    account: '',
    secret: input,
    digits: null,
    period: null,
    algorithm: 'SHA-1',
  };
}

function normalizeAlgorithm(name) {
  const normalized = name.replace(/-/g, '').toUpperCase();
  if (normalized === 'SHA1') {
    return 'SHA-1';
  }
  if (normalized === 'SHA256') {
    return 'SHA-256';
  }
  if (normalized === 'SHA512') {
    return 'SHA-512';
  }
  return 'SHA-1';
}

function base32ToBytes(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = input.replace(/=+$/g, '').replace(/[\s-]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const output = [];

  for (const char of cleaned) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) {
      throw new Error('Secret 不是有效的 Base32。');
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      output.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(output);
}

async function generateTotp(secretBytes, period, digits, algorithm, timestampMs) {
  const counter = Math.floor(timestampMs / 1000 / period);
  const counterBytes = new Uint8Array(8);
  let temp = counter;
  for (let i = 7; i >= 0; i -= 1) {
    counterBytes[i] = temp & 0xff;
    temp = Math.floor(temp / 256);
  }

  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: { name: algorithm } },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = mac[mac.length - 1] & 0x0f;
  const binCode =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  const otp = (binCode % 10 ** digits).toString().padStart(digits, '0');
  return otp;
}

function bytesToBase64url(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlToBytes(base64url) {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function coerceToBytes(value, label) {
  if (value == null) {
    throw new Error(`注册参数缺失：${label}`);
  }
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }
  if (typeof value === 'object') {
    if (value.type === 'Buffer' && Array.isArray(value.data)) {
      return new Uint8Array(value.data);
    }
    const numericValues = Object.values(value);
    if (numericValues.length && numericValues.every((item) => Number.isInteger(item))) {
      return new Uint8Array(numericValues);
    }
  }
  if (typeof value === 'string') {
    return base64urlToBytes(value);
  }
  throw new Error(`无法解析注册参数：${label}`);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || `请求失败 (${response.status})`);
  }
  return response.json();
}
