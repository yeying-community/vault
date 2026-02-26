import express from 'express';
import session from 'express-session';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'webauthn.json');

const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || 'http://localhost:3000';
const rpName = 'Web Authenticator';
const port = Number(process.env.PORT) || 3000;

const app = express();
app.disable('x-powered-by');

app.use(express.json({ limit: '1mb' }));

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('[warn] SESSION_SECRET not set. Using a random secret for this process.');
}

app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    },
  }),
);

app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self'",
      "connect-src 'self'",
      "form-action 'self'",
    ].join('; '),
  );
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Permissions-Policy',
    'publickey-credentials-get=(self), publickey-credentials-create=(self)',
  );
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
});

app.use(express.static(PUBLIC_DIR, { index: false }));

app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.get('/api/time', (req, res) => {
  res.json({ now: Date.now() });
});

app.get('/api/webauthn/status', async (req, res) => {
  const data = await loadData();
  res.json({ registered: hasValidCredential(data) });
});

app.post('/api/webauthn/register/options', async (req, res) => {
  const data = (await loadData()) || {};
  const hasCredential = hasValidCredential(data);
  if (!hasCredential && data.credential) {
    data.credential = null;
    await saveData(data);
  }

  if (hasCredential && !req.body?.force) {
    res.status(409).json({ error: 'Passkey already registered.' });
    return;
  }

  const user =
    data.user?.id
      ? data.user
      : (() => {
          const userIdBytes = crypto.randomBytes(16);
          return {
            id: bufferToBase64url(userIdBytes),
            name: 'local-user',
            displayName: 'Local User',
          };
        })();

  const excludeCredentials = hasCredential
    ? [
        {
          // @simplewebauthn/server v11 expects a base64url string here.
          id: data.credential.id,
          type: 'public-key',
          transports: data.credential.transports || ['internal'],
        },
      ]
    : [];

  let options;
  try {
    options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: base64urlToBuffer(user.id),
      userName: user.name,
      userDisplayName: user.displayName,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7, -257],
      excludeCredentials,
    });
  } catch (err) {
    res.status(500).json({ error: err?.message || 'Failed to create registration options.' });
    return;
  }

  req.session.currentChallenge = options.challenge;
  req.session.challengeType = 'registration';

  data.user = user;
  await saveData(data);

  res.json(options);
});

app.post('/api/webauthn/register/verify', async (req, res) => {
  const data = (await loadData()) || {};
  const expectedChallenge = req.session.currentChallenge;
  if (!expectedChallenge || req.session.challengeType !== 'registration') {
    res.status(400).json({ error: 'Missing registration challenge.' });
    return;
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (err) {
    res.status(400).json({ error: err?.message || 'Registration verification failed.' });
    return;
  }

  const { verified, registrationInfo } = verification;
  if (!verified || !registrationInfo) {
    res.status(400).json({ error: 'Registration not verified.' });
    return;
  }

  let credentialId = '';
  let credentialPublicKeyB64 = '';
  let counter = 0;
  let transports = req.body?.response?.transports || ['internal'];

  if (registrationInfo.credential) {
    credentialId = registrationInfo.credential.id || '';
    counter =
      typeof registrationInfo.credential.counter === 'number'
        ? registrationInfo.credential.counter
        : registrationInfo.counter || 0;
    if (registrationInfo.credential.publicKey) {
      credentialPublicKeyB64 =
        typeof registrationInfo.credential.publicKey === 'string'
          ? registrationInfo.credential.publicKey
          : bufferToBase64url(registrationInfo.credential.publicKey);
    }
    if (Array.isArray(registrationInfo.credential.transports)) {
      transports = registrationInfo.credential.transports;
    }
  } else {
    const { credentialID, credentialPublicKey, counter: legacyCounter } = registrationInfo;
    credentialId = bufferToBase64url(credentialID);
    credentialPublicKeyB64 = bufferToBase64url(credentialPublicKey);
    counter = typeof legacyCounter === 'number' ? legacyCounter : 0;
  }

  if (!credentialId || !credentialPublicKeyB64) {
    res.status(400).json({ error: 'Registration data incomplete.' });
    return;
  }

  data.credential = {
    id: credentialId,
    publicKey: credentialPublicKeyB64,
    counter,
    transports,
  };

  if (!data.prfSalt) {
    data.prfSalt = bufferToBase64url(crypto.randomBytes(32));
  }

  await saveData(data);

  req.session.currentChallenge = null;
  req.session.challengeType = null;

  res.json({ verified: true });
});

app.post('/api/webauthn/authenticate/options', async (req, res) => {
  const data = await loadData();
  if (!hasValidCredential(data)) {
    if (data?.credential) {
      data.credential = null;
      await saveData(data);
    }
    res.status(400).json({ error: 'No valid passkey registered.' });
    return;
  }

  let options;
  try {
    options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'required',
      allowCredentials: [
        {
          // Keep credential ID as base64url string; converting to Buffer breaks v11 validation.
          id: data.credential.id,
          type: 'public-key',
          transports: data.credential.transports || ['internal'],
        },
      ],
    });
  } catch (err) {
    res.status(500).json({ error: err?.message || 'Failed to create authentication options.' });
    return;
  }

  req.session.currentChallenge = options.challenge;
  req.session.challengeType = 'authentication';

  res.json({ ...options, prfSalt: data.prfSalt });
});

app.post('/api/webauthn/authenticate/verify', async (req, res) => {
  const data = await loadData();
  if (!hasValidCredential(data)) {
    res.status(400).json({ error: 'No valid passkey registered.' });
    return;
  }

  const expectedChallenge = req.session.currentChallenge;
  if (!expectedChallenge || req.session.challengeType !== 'authentication') {
    res.status(400).json({ error: 'Missing authentication challenge.' });
    return;
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
      // v11 uses `credential` instead of legacy `authenticator` payload shape.
      credential: {
        id: data.credential.id,
        publicKey: base64urlToBuffer(data.credential.publicKey),
        counter: data.credential.counter,
        transports: data.credential.transports || ['internal'],
      },
    });
  } catch (err) {
    res.status(400).json({ error: err?.message || 'Authentication verification failed.' });
    return;
  }

  const { verified, authenticationInfo } = verification;
  if (!verified || !authenticationInfo) {
    res.status(400).json({ error: 'Authentication not verified.' });
    return;
  }

  data.credential.counter = authenticationInfo.newCounter;
  await saveData(data);

  req.session.currentChallenge = null;
  req.session.challengeType = null;

  res.json({ verified: true });
});

app.listen(port, () => {
  console.log(`[info] Web Authenticator running on ${origin}`);
});

async function loadData() {
  try {
    const raw = await fs.readFile(DATA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err?.code === 'ENOENT') {
      return null;
    }
    throw err;
  }
}

async function saveData(data) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function bufferToBase64url(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return Buffer.from(binary, 'binary')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64urlToBuffer(base64url) {
  if (base64url instanceof Uint8Array) {
    return Buffer.from(base64url);
  }
  if (base64url instanceof ArrayBuffer) {
    return Buffer.from(new Uint8Array(base64url));
  }
  if (Array.isArray(base64url)) {
    return Buffer.from(base64url);
  }
  if (base64url && typeof base64url === 'object') {
    if (base64url.type === 'Buffer' && Array.isArray(base64url.data)) {
      return Buffer.from(base64url.data);
    }
  }
  if (typeof base64url !== 'string') {
    throw new Error('Invalid base64url input.');
  }
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64');
}

function hasValidCredential(data) {
  return Boolean(
    data?.credential &&
      typeof data.credential.id === 'string' &&
      data.credential.id.length > 0 &&
      typeof data.credential.publicKey === 'string' &&
      data.credential.publicKey.length > 0,
  );
}
