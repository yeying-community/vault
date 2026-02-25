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
  res.json({ registered: Boolean(data?.credential) });
});

app.post('/api/webauthn/register/options', async (req, res) => {
  const data = (await loadData()) || {};
  if (data.credential && !req.body?.force) {
    res.status(409).json({ error: 'Passkey already registered.' });
    return;
  }

  const user =
    data.user ||
    (() => {
      const userIdBytes = crypto.randomBytes(16);
      return {
        id: bufferToBase64url(userIdBytes),
        name: 'local-user',
        displayName: 'Local User',
      };
    })();

  const excludeCredentials = data.credential
    ? [
        {
          id: base64urlToBuffer(data.credential.id),
          type: 'public-key',
          transports: data.credential.transports || ['internal'],
        },
      ]
    : [];

  const options = generateRegistrationOptions({
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

  const { credentialID, credentialPublicKey, counter } = registrationInfo;

  data.credential = {
    id: bufferToBase64url(credentialID),
    publicKey: bufferToBase64url(credentialPublicKey),
    counter,
    transports: req.body?.response?.transports || ['internal'],
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
  if (!data?.credential) {
    res.status(400).json({ error: 'No passkey registered.' });
    return;
  }

  const options = generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
    allowCredentials: [
      {
        id: base64urlToBuffer(data.credential.id),
        type: 'public-key',
        transports: data.credential.transports || ['internal'],
      },
    ],
  });

  req.session.currentChallenge = options.challenge;
  req.session.challengeType = 'authentication';

  res.json({ ...options, prfSalt: data.prfSalt });
});

app.post('/api/webauthn/authenticate/verify', async (req, res) => {
  const data = await loadData();
  if (!data?.credential) {
    res.status(400).json({ error: 'No passkey registered.' });
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
      authenticator: {
        credentialID: base64urlToBuffer(data.credential.id),
        credentialPublicKey: base64urlToBuffer(data.credential.publicKey),
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
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64');
}
