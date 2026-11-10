require('dotenv').config();
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const QRCode = require('qrcode');
const helmet = require('helmet');
const multer = require('multer');
const yazl = require('yazl');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const SUBMISSIONS_DIR = path.join(DATA_DIR, 'submissions');
const PROFILE_PICTURES_DIR = path.join(DATA_DIR, 'profile-pictures');
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'attendance.json');
const defaultState = {
  nextIds: { users: 1, sessions: 1, attendance: 1, qrTokens: 1, sections: 1, tasks: 1, submissions: 1, activityLogs: 1 },
  users: [],
  sessions: [],
  attendance: [],
  qrTokens: [],
  passwordResetTokens: [],
  sections: [],
  tasks: [],
  submissions: [],
  activityLogs: []
};

function readState() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(defaultState, null, 2));
    return JSON.parse(JSON.stringify(defaultState));
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    return { ...defaultState, ...parsed, nextIds: { ...defaultState.nextIds, ...(parsed.nextIds || {}) } };
  } catch (error) {
    fs.writeFileSync(DB_PATH, JSON.stringify(defaultState, null, 2));
    return JSON.parse(JSON.stringify(defaultState));
  }
}

function writeState(state) {
  fs.writeFileSync(DB_PATH, JSON.stringify(state, null, 2));
}

function nextId(state, key) {
  const id = state.nextIds[key] || 1;
  state.nextIds[key] = id + 1;
  return id;
}

function addActivityLog(state, action, details = '', actorId = null, actorName = '') {
  state.activityLogs.push({
    id: nextId(state, 'activityLogs'),
    action,
    details,
    actorId,
    actorName,
    createdAt: new Date().toISOString()
  });
}

function getUserByEmail(state, email) {
  return state.users.find(user => user.email.toLowerCase() === String(email).trim().toLowerCase());
}

function getUserById(state, id) {
  return state.users.find(user => user.id === Number(id));
}

const sessionSecret = process.env.SESSION_SECRET;
if (process.env.NODE_ENV === 'production' && (!sessionSecret || sessionSecret.length < 32)) {
  throw new Error('Set SESSION_SECRET to a random value of at least 32 characters in production.');
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(session({
  name: 'nstp.sid',
  secret: sessionSecret || 'local-development-secret-change-this-before-deploying',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(ROOT, 'public')));
app.use('/vendor', express.static(path.join(ROOT, 'node_modules', 'jsqr', 'dist')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });
const passwordResetLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false });
const adminMfaLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false });
const submissionLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });
const profilePictureLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
const adminEmailMfa = process.env.ADMIN_EMAIL_MFA === 'true';
const uploadSubmission = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 }
});
const uploadProfilePicture = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 }
});
const profilePictureTypes = {
  'image/jpeg': { extension: 'jpg', matches: buffer => buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff },
  'image/png': { extension: 'png', matches: buffer => buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  'image/webp': { extension: 'webp', matches: buffer => buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP' }
};
const fail = (res, status, message) => res.status(status).json({ error: message });
const csrfToken = () => crypto.randomBytes(32).toString('hex');

function ensureDefaultAdmin() {
  const state = readState();
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@nstp.local').trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin12345!';
  const adminUsername = (process.env.ADMIN_USERNAME || adminEmail.split('@')[0]).trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,32}$/.test(adminUsername)) {
    throw new Error('ADMIN_USERNAME must be 3–32 characters and use only letters, numbers, dots, underscores, or hyphens.');
  }
  const existingAdmin = state.users.find(user => user.email.toLowerCase() === adminEmail);
  if (!existingAdmin) {
    if (state.users.some(user => user.role === 'admin' && user.username?.toLowerCase() === adminUsername)) {
      throw new Error('ADMIN_USERNAME is already used by another administrator.');
    }
    state.users.push({
      id: nextId(state, 'users'),
      name: 'NSTP Administrator',
      email: adminEmail,
      username: adminUsername,
      password_hash: bcrypt.hashSync(adminPassword, 12),
      role: 'admin',
      created_at: new Date().toISOString()
    });
    writeState(state);
  } else if (existingAdmin.role === 'admin' && !existingAdmin.username) {
    if (state.users.some(user => user !== existingAdmin && user.role === 'admin' && user.username?.toLowerCase() === adminUsername)) {
      throw new Error('ADMIN_USERNAME is already used by another administrator.');
    }
    existingAdmin.username = adminUsername;
    writeState(state);
  }
}
ensureDefaultAdmin();

function ensureDefaultSections() {
  const state = readState();
  const defaultSections = ['BSIT 1A WMAD'];
  let changed = false;
  for (const name of defaultSections) {
    if (state.sections.some(section => section.name.toLowerCase() === name.toLowerCase())) continue;
    state.sections.push({ id: nextId(state, 'sections'), name, created_at: new Date().toISOString() });
    changed = true;
  }
  if (changed) writeState(state);
}
ensureDefaultSections();

app.get('/api/csrf', (req, res) => {
  req.session.csrfToken ||= csrfToken();
  res.json({ token: req.session.csrfToken });
});

app.get('/api/captcha', (req, res) => {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const answer = Array.from({ length: 6 }, () => alphabet[crypto.randomInt(alphabet.length)]).join('');
  req.session.captcha = {
    answer,
    expiresAt: Date.now() + 5 * 60 * 1000
  };
  res.json({ question: answer });
});

app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const provided = req.get('x-csrf-token') || '';
  const expected = req.session.csrfToken || '';
  const a = Buffer.from(provided); const b = Buffer.from(expected);
  if (!a.length || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return fail(res, 403, 'Security token missing or expired. Refresh and try again.');
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) return fail(res, 401, 'Please sign in first.');
  if (req.session.user.mustChangePassword && !['/api/student/password', '/api/auth/logout'].includes(req.path)) {
    return fail(res, 403, 'Set a private password before using your account.');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user?.role !== 'admin') return fail(res, 403, 'Administrator access required.');
  next();
}

function requireStudent(req, res, next) {
  if (req.session.user?.role !== 'student') return fail(res, 403, 'Student access required.');
  next();
}

function verifyCaptcha(req, res, next) {
  const challenge = req.session.captcha;
  delete req.session.captcha;
  const answer = String(req.body.captchaAnswer || '').trim().toUpperCase();
  if (!challenge || Date.now() >= challenge.expiresAt || answer !== challenge.answer) {
    return fail(res, 400, 'CAPTCHA answer is incorrect or expired. Please try again.');
  }
  next();
}

function safeUser(user, state) {
  const safe = { id: user.id, name: user.name, email: user.email, role: user.role };
  if (user.role === 'student') {
    safe.section = state?.sections.find(section => section.id === user.sectionId)?.name || '';
    safe.hasProfilePicture = Boolean(user.profilePictureType);
    safe.mustChangePassword = user.mustChangePassword !== false;
  }
  return safe;
}

function cleanSession(row) {
  return { ...row, active: Boolean(row.active) };
}

function parseSectionId(value) {
  if (value === undefined || value === null || value === '') return null;
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : NaN;
}

function localDateString(date = new Date()) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

function isValidDateString(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function sessionStartTimestamp(session) {
  if (session.start_at) {
    const timestamp = new Date(session.start_at).getTime();
    if (Number.isFinite(timestamp)) return timestamp;
  }
  if (!session.start_time) return null;
  const timestamp = new Date(`${session.event_date}T${session.start_time}:00`).getTime();
  return Number.isFinite(timestamp) ? timestamp : null;
}

function isLateForSession(session, checkIn) {
  const start = sessionStartTimestamp(session);
  if (start === null || !checkIn) return false;
  const arrival = new Date(checkIn).getTime();
  return Number.isFinite(start) && Number.isFinite(arrival) && arrival > start;
}

function uploadError(error, req, res, next) {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') return fail(res, 413, 'PDF files must be 10 MB or smaller.');
    return fail(res, 400, 'Upload one PDF file at a time.');
  }
  next(error);
}

function handleSubmissionUpload(req, res, next) {
  uploadSubmission.single('file')(req, res, error => {
    if (error) return uploadError(error, req, res, next);
    next();
  });
}

function handleProfilePictureUpload(req, res, next) {
  uploadProfilePicture.single('profilePicture')(req, res, error => {
    if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
      return fail(res, 413, 'Profile pictures must be 5 MB or smaller.');
    }
    if (error instanceof multer.MulterError) return fail(res, 400, 'Upload one profile picture at a time.');
    if (error) return uploadError(error, req, res, next);
    next();
  });
}

app.post('/api/auth/register', authLimiter, verifyCaptcha, (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const studentNumber = String(req.body.studentNumber || '').trim().toUpperCase();
  const password = String(req.body.password || '');
  const requestedSectionId = parseSectionId(req.body.sectionId);
  const sectionName = String(req.body.sectionName || '').trim().replace(/\s+/g, ' ');
  if (name.length < 2 || name.length > 80) return fail(res, 400, 'Name must be between 2 and 80 characters.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return fail(res, 400, 'Enter a valid personal email address.');
  if (!/^[A-Z0-9-]{4,32}$/.test(studentNumber)) return fail(res, 400, 'Enter a valid student number (4–32 letters, numbers, or hyphens).');
  if (password.length < 10 || password.length > 128) return fail(res, 400, 'Choose a password with 10–128 characters.');
  if (sectionName && (sectionName.length < 2 || sectionName.length > 80)) return fail(res, 400, 'Section name must be between 2 and 80 characters.');

  const state = readState();
  let section = sectionName
    ? state.sections.find(item => item.name.toLowerCase() === sectionName.toLowerCase())
    : Number.isInteger(requestedSectionId)
      ? state.sections.find(item => item.id === requestedSectionId)
      : null;
  if (!section && !sectionName) return fail(res, 400, 'Enter a valid student section.');
  const studentNumberHash = crypto.createHmac('sha256', sessionSecret || 'local-development-secret-change-this-before-deploying').update(studentNumber).digest('hex');
  if (state.users.some(user => user.studentNumberHash === studentNumberHash)) return fail(res, 409, 'An account with that student number already exists.');
  if (getUserByEmail(state, email)) return fail(res, 409, 'An account with that email already exists.');
  if (!section) {
    section = { id: nextId(state, 'sections'), name: sectionName, created_at: new Date().toISOString() };
    state.sections.push(section);
  }

  const user = {
    id: nextId(state, 'users'),
    name,
    email,
    password_hash: bcrypt.hashSync(password, 12),
    role: 'student',
    sectionId: section.id,
    studentNumberHash,
    mustChangePassword: false,
    created_at: new Date().toISOString()
  };
  state.users.push(user);
  addActivityLog(state, 'student_registered', `${name} registered for ${section.name}.`, user.id, name);
  writeState(state);

  req.session.regenerate((err) => {
    if (err) return fail(res, 500, 'Could not start your session.');
    req.session.user = safeUser(user, state);
    req.session.csrfToken = csrfToken();
    res.status(201).json({ user: req.session.user, csrfToken: req.session.csrfToken });
  });
});

app.post('/api/auth/login', authLimiter, verifyCaptcha, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const role = String(req.body.role || '');
  if (!['student', 'admin'].includes(role)) return fail(res, 400, 'Choose whether to sign in as a student or admin.');
  const state = readState();
  const user = role === 'admin'
    ? state.users.find(item => item.role === 'admin' && item.username?.toLowerCase() === username) || getUserByEmail(state, email)
    : getUserByEmail(state, email);
  const storedStudentNumberHash = user?.studentNumberHash;
  const submittedStudentNumberHash = role === 'student' && user && storedStudentNumberHash
    ? crypto.createHmac('sha256', sessionSecret || 'local-development-secret-change-this-before-deploying')
      .update(password.trim().toUpperCase()).digest('hex')
    : '';
  const studentPasswordMatches = role === 'student' && Boolean(user) && /^[a-f0-9]{64}$/i.test(storedStudentNumberHash || '') &&
    crypto.timingSafeEqual(Buffer.from(submittedStudentNumberHash, 'hex'), Buffer.from(storedStudentNumberHash, 'hex'));
  const mustChangePassword = role === 'student' && Boolean(storedStudentNumberHash) && user.mustChangePassword !== false;
  const passwordMatches = mustChangePassword
    ? studentPasswordMatches
    : Boolean(user && bcrypt.compareSync(password, user.password_hash));
  if (!user || user.role !== role || !passwordMatches) {
    return fail(res, 401, 'Username/email, password, or selected account type is incorrect.');
  }

  if (mustChangePassword) user.mustChangePassword = true;
  if (role === 'admin' && adminEmailMfa) {
    const smtpHost = process.env.SMTP_HOST;
    const smtpPort = Number(process.env.SMTP_PORT || 587);
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    const from = process.env.SMTP_FROM;
    const secure = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true';
    if (!smtpHost || !Number.isInteger(smtpPort) || smtpPort < 1 || smtpPort > 65535 ||
        Boolean(smtpUser) !== Boolean(smtpPass) || !from) {
      return fail(res, 503, 'Admin email verification is not configured. Contact the app administrator.');
    }

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = crypto.createHmac('sha256', sessionSecret || 'local-development-secret-change-this-before-deploying').update(code).digest('hex');
    req.session.regenerate(async error => {
      if (error) return fail(res, 500, 'Could not start your verification session.');
      req.session.pendingAdminMfa = { userId: user.id, codeHash, expiresAt: Date.now() + 5 * 60 * 1000, attempts: 0 };
      req.session.csrfToken = csrfToken();
      try {
        const transporter = nodemailer.createTransport({
          host: smtpHost,
          port: smtpPort,
          secure,
          ...(smtpUser ? { auth: { user: smtpUser, pass: smtpPass } } : {})
        });
        await transporter.sendMail({
          from,
          to: user.email,
          subject: 'Your NSTP Attendance sign-in code',
          text: `Your administrator sign-in code is ${code}. It expires in 5 minutes. If you did not try to sign in, you can ignore this email.`
        });
        return res.json({ requiresTwoFactor: true, csrfToken: req.session.csrfToken });
      } catch (error) {
        console.error('Admin sign-in code delivery failed:', error);
        req.session.destroy(() => {
          res.clearCookie('nstp.sid', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
          fail(res, 503, 'Could not send the admin sign-in code. Check the email configuration and try again.');
        });
      }
    });
    return;
  }

  addActivityLog(state, 'user_login', `${user.name} signed in as ${role}.`, user.id, user.name);
  writeState(state);

  req.session.regenerate((err) => {
    if (err) return fail(res, 500, 'Could not start your session.');
    req.session.user = safeUser(user, state);
    req.session.csrfToken = csrfToken();
    res.json({ user: req.session.user, csrfToken: req.session.csrfToken });
  });
});

app.post('/api/auth/admin/verify-two-factor', adminMfaLimiter, (req, res) => {
  const pending = req.session.pendingAdminMfa;
  if (!pending || pending.expiresAt <= Date.now()) {
    delete req.session.pendingAdminMfa;
    return fail(res, 401, 'The verification code expired. Sign in again to request a new one.');
  }
  const code = String(req.body.code || '').trim();
  if (!/^\d{6}$/.test(code)) return fail(res, 400, 'Enter the six-digit code from your email.');
  const submittedHash = crypto.createHmac('sha256', sessionSecret || 'local-development-secret-change-this-before-deploying').update(code).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(submittedHash, 'hex'), Buffer.from(pending.codeHash, 'hex'))) {
    pending.attempts += 1;
    if (pending.attempts >= 5) delete req.session.pendingAdminMfa;
    return fail(res, 401, pending.attempts >= 5
      ? 'Too many incorrect codes. Sign in again to request a new one.'
      : 'That verification code is incorrect.');
  }

  const state = readState();
  const user = getUserById(state, pending.userId);
  if (!user || user.role !== 'admin') {
    delete req.session.pendingAdminMfa;
    return fail(res, 401, 'The administrator account is no longer available. Sign in again.');
  }
  addActivityLog(state, 'user_login', `${user.name} signed in as admin with email verification.`, user.id, user.name);
  writeState(state);
  req.session.regenerate(error => {
    if (error) return fail(res, 500, 'Could not complete your sign-in.');
    req.session.user = safeUser(user, state);
    req.session.csrfToken = csrfToken();
    res.json({ user: req.session.user, csrfToken: req.session.csrfToken });
  });
});

app.post('/api/admin/admins', requireAuth, requireAdmin, authLimiter, (req, res) => {
  return fail(res, 403, 'This app uses one administrator account. Additional admin accounts cannot be created.');
});

app.post('/api/auth/forgot-password', passwordResetLimiter, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const role = String(req.body.role || '');
  if (!['student', 'admin'].includes(role)) return fail(res, 400, 'Choose whether to recover a student or admin account.');
  const remoteAddress = req.socket.remoteAddress || '';
  const isLocalDevelopment = process.env.NODE_ENV !== 'production' &&
    (remoteAddress === '::1' || remoteAddress.startsWith('127.') || remoteAddress.startsWith('::ffff:127.'));
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = Number(process.env.SMTP_PORT || 587);
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const from = process.env.SMTP_FROM;
  const baseUrl = process.env.APP_BASE_URL;
  const secure = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true';
  const validBaseUrl = (() => {
    try {
      const url = new URL(baseUrl);
      return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
    } catch {
      return false;
    }
  })();
  const smtpConfigured = Boolean(smtpHost && smtpHost !== 'smtp.example.com' &&
    Number.isInteger(smtpPort) && smtpPort >= 1 && smtpPort <= 65535 &&
    Boolean(smtpUser) === Boolean(smtpPass) && from && from !== 'NSTP Attendance <no-reply@example.com>' &&
    validBaseUrl);
  if (!smtpConfigured && !isLocalDevelopment) {
    return fail(res, 503, 'Password reset email is not configured. Contact the app administrator.');
  }

  const state = readState();
  const matchedUser = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? getUserByEmail(state, email) : null;
  const user = matchedUser?.role === role ? matchedUser : null;
  let devResetUrl = '';
  if (user) {
    const now = Date.now();
    state.passwordResetTokens = state.passwordResetTokens.filter(item => item.expiresAt > now);
    const recentlyRequested = state.passwordResetTokens.some(item => item.userId === user.id && item.createdAt > now - 60 * 1000);
    if (!recentlyRequested) {
      const token = crypto.randomBytes(32).toString('base64url');
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      state.passwordResetTokens = state.passwordResetTokens.filter(item => item.userId !== user.id);
      state.passwordResetTokens.push({ userId: user.id, tokenHash, createdAt: now, expiresAt: now + 30 * 60 * 1000 });
      writeState(state);

      const makeResetUrl = () => {
        const resetUrl = new URL(isLocalDevelopment ? `http://localhost:${PORT}` : baseUrl);
        resetUrl.hash = new URLSearchParams({ reset: token }).toString();
        return resetUrl;
      };
      if (smtpConfigured) {
        try {
          const transporter = nodemailer.createTransport({
            host: smtpHost,
            port: smtpPort,
            secure,
            connectionTimeout: 10000,
            greetingTimeout: 10000,
            socketTimeout: 15000,
            ...(smtpUser ? { auth: { user: smtpUser, pass: smtpPass } } : {})
          });
          const resetUrl = makeResetUrl();
          const safeName = user.name.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
          await transporter.sendMail({
            from,
            to: user.email,
            subject: 'Reset your NSTP Attendance password',
            text: `Hello ${user.name},\n\nUse this link to reset your NSTP Attendance password. It expires in 30 minutes and can only be used once:\n${resetUrl.href}\n\nIf you did not request a password reset, you can ignore this email.`,
            html: `<p>Hello ${safeName},</p><p>Use the link below to reset your NSTP Attendance password. It expires in 30 minutes and can only be used once.</p><p><a href="${resetUrl.href.replace(/&/g, '&amp;')}">Reset your password</a></p><p>If you did not request a password reset, you can ignore this email.</p>`
          });
        } catch (error) {
          console.error('Password reset email delivery failed:', error);
          if (isLocalDevelopment) {
            devResetUrl = makeResetUrl().href;
          } else {
            state.passwordResetTokens = state.passwordResetTokens.filter(item => item.tokenHash !== tokenHash);
            writeState(state);
          }
        }
      } else {
        devResetUrl = makeResetUrl().href;
      }
    }
  }
  res.json({
    ok: true,
    message: devResetUrl
      ? 'Email delivery is unavailable. Use the local password-reset form to choose a new password.'
      : 'If an account exists for that email, a password-reset link will be sent shortly.',
    ...(devResetUrl ? { devResetUrl } : {})
  });
});

app.post('/api/auth/reset-password', passwordResetLimiter, (req, res) => {
  const token = String(req.body.token || '');
  const password = String(req.body.password || '');
  if (password.length < 10 || password.length > 128) return fail(res, 400, 'Password must be 10–128 characters.');
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return fail(res, 400, 'This password-reset link is invalid or expired. Request a new one.');

  const state = readState();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const reset = state.passwordResetTokens.find(item => item.tokenHash === tokenHash && item.expiresAt > Date.now());
  if (!reset) return fail(res, 400, 'This password-reset link is invalid or expired. Request a new one.');
  const user = getUserById(state, reset.userId);
  if (!user) return fail(res, 400, 'This password-reset link is invalid or expired. Request a new one.');

  user.password_hash = bcrypt.hashSync(password, 12);
  if (user.role === 'student') user.mustChangePassword = false;
  state.passwordResetTokens = state.passwordResetTokens.filter(item => item.userId !== user.id);
  addActivityLog(state, 'password_reset', `${user.name} reset their password.`, user.id, user.name);
  writeState(state);
  res.json({ ok: true });
});

app.post('/api/student/password', requireAuth, requireStudent, (req, res) => {
  const currentPassword = String(req.body.currentPassword || '').trim().toUpperCase();
  const password = String(req.body.password || '');
  if (password.length < 10 || password.length > 128) return fail(res, 400, 'Choose a private password with 10–128 characters.');
  if (!req.session.user.mustChangePassword) return fail(res, 400, 'Your account does not require an initial password change.');

  const state = readState();
  const user = getUserById(state, req.session.user.id);
  if (!user || user.role !== 'student') return fail(res, 404, 'Student account not found.');
  const currentPasswordHash = crypto.createHmac('sha256', sessionSecret || 'local-development-secret-change-this-before-deploying')
   .update(currentPassword).digest('hex');
  const currentPasswordMatches = /^[a-f0-9]{64}$/i.test(user.studentNumberHash || '') &&
   crypto.timingSafeEqual(Buffer.from(currentPasswordHash, 'hex'), Buffer.from(user.studentNumberHash, 'hex'));
  if (!currentPasswordMatches) return fail(res, 401, 'The temporary student-number password is incorrect.');
  if (password.trim().toUpperCase() === currentPassword) return fail(res, 400, 'Choose a password different from your student number.');

  user.password_hash = bcrypt.hashSync(password, 12);
  user.mustChangePassword = false;
  addActivityLog(state, 'student_password_changed', `${user.name} set a private password.`, user.id, user.name);
  writeState(state);
  req.session.user = safeUser(user, state);
  res.json({ user: req.session.user });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('nstp.sid', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
    res.json({ ok: true });
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  if (req.session.user.role === 'student') {
    const state = readState();
    const user = getUserById(state, req.session.user.id);
    return res.json({ user: { ...req.session.user, section: state.sections.find(section => section.id === user?.sectionId)?.name || '' } });
  }
  res.json({ user: req.session.user });
});

app.put('/api/student/profile', requireAuth, requireStudent, profilePictureLimiter, handleProfilePictureUpload, (req, res) => {
  const name = String(req.body.name || '').trim().replace(/\s+/g, ' ');
  const email = String(req.body.email || '').trim().toLowerCase();
  if (name.length < 2 || name.length > 80) return fail(res, 400, 'Name must be between 2 and 80 characters.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return fail(res, 400, 'Enter a valid email address.');

  const state = readState();
  const user = getUserById(state, req.session.user.id);
  if (!user || user.role !== 'student') return fail(res, 404, 'Student account not found.');
  const existingUser = getUserByEmail(state, email);
  if (existingUser && existingUser.id !== user.id) return fail(res, 409, 'An account with that email already exists.');

  let savedPicturePath = '';
  const previousPicturePath = user.profilePictureFile
    ? path.join(PROFILE_PICTURES_DIR, path.basename(user.profilePictureFile))
    : '';
  if (req.file) {
    const pictureType = profilePictureTypes[req.file.mimetype];
    if (!pictureType || !pictureType.matches(req.file.buffer)) {
      return fail(res, 400, 'Upload a valid JPG, PNG, or WebP image.');
    }
    fs.mkdirSync(PROFILE_PICTURES_DIR, { recursive: true });
    const pictureFile = `${user.id}-${crypto.randomUUID()}.${pictureType.extension}`;
    const picturePath = path.join(PROFILE_PICTURES_DIR, pictureFile);
    fs.writeFileSync(picturePath, req.file.buffer);
    savedPicturePath = picturePath;
    user.profilePictureFile = pictureFile;
    user.profilePictureType = req.file.mimetype;
  }

  user.name = name;
  user.email = email;
  try {
    writeState(state);
  } catch (error) {
    if (savedPicturePath) {
      try { fs.unlinkSync(savedPicturePath); } catch (cleanupError) {
        if (cleanupError.code !== 'ENOENT') throw cleanupError;
      }
    }
    throw error;
  }
  if (req.file && previousPicturePath && previousPicturePath !== savedPicturePath) {
    try { fs.unlinkSync(previousPicturePath); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  addActivityLog(state, 'profile_updated', `${user.name} updated their student profile information.`, user.id, user.name);
  req.session.user = safeUser(user, state);
  res.json({ user: req.session.user });
});

app.get('/api/student/profile-picture', requireAuth, (req, res, next) => {
  if (req.session.user.role !== 'student') return fail(res, 403, 'Student access required.');
  const state = readState();
  const user = getUserById(state, req.session.user.id);
  const pictureType = profilePictureTypes[user?.profilePictureType];
  if (!user || !pictureType) return fail(res, 404, 'Profile picture not found.');

  if (path.basename(user.profilePictureFile || '') !== user.profilePictureFile ||
      path.extname(user.profilePictureFile) !== `.${pictureType.extension}`) return fail(res, 404, 'Profile picture not found.');
  const picturePath = path.join(PROFILE_PICTURES_DIR, user.profilePictureFile);
  res.set({ 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' });
  res.type(pictureType.extension === 'jpg' ? 'image/jpeg' : `image/${pictureType.extension}`);
  res.sendFile(picturePath, error => {
    if (error && !res.headersSent) {
      if (error.code === 'ENOENT') return fail(res, 404, 'Profile picture not found.');
      next(error);
    }
  });
});

app.get('/api/sections', (req, res) => {
  const state = readState();
  const sections = state.sections.slice().sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
  if (req.session.user?.role === 'admin') {
    return res.json({ sections: sections.map(section => ({
      ...section,
      student_count: state.users.filter(user => user.role === 'student' && user.sectionId === section.id).length
    })) });
  }
  res.json({ sections: sections.map(({ id, name }) => ({ id, name })) });
});

app.post('/api/sections', requireAuth, requireAdmin, (req, res) => {
  const name = String(req.body.name || '').trim().replace(/\s+/g, ' ');
  if (name.length < 2 || name.length > 80) return fail(res, 400, 'Section name must be between 2 and 80 characters.');
  const state = readState();
  if (state.sections.some(section => section.name.toLowerCase() === name.toLowerCase())) return fail(res, 409, 'That section already exists.');
  const section = { id: nextId(state, 'sections'), name, created_at: new Date().toISOString() };
  state.sections.push(section);
  addActivityLog(state, 'section_created', `New section created: ${name}.`, req.session.user.id, req.session.user.name);
  writeState(state);
  res.status(201).json({ section });
});

app.delete('/api/sections/:id', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const state = readState();
  const index = state.sections.findIndex(section => section.id === id);
  if (index === -1) return fail(res, 404, 'Section not found.');
  if (state.users.some(user => user.role === 'student' && user.sectionId === id) ||
      state.sessions.some(session => session.sectionId === id) ||
      state.tasks.some(task => task.sectionId === id)) {
    return fail(res, 409, 'This section is assigned to students, sessions, or tasks and cannot be deleted.');
  }
  state.sections.splice(index, 1);
  writeState(state);
  res.json({ ok: true });
});

app.get('/api/sections/:id/students', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const state = readState();
  const section = state.sections.find(item => item.id === id);
  if (!section) return fail(res, 404, 'Section not found.');
  const students = state.users.filter(user => user.role === 'student' && user.sectionId === id)
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }))
    .map(user => ({ id: user.id, name: user.name, email: user.email }));
  res.json({ section, students });
});

app.get('/api/admin/students/unassigned', requireAuth, requireAdmin, (req, res) => {
  const state = readState();
  const students = state.users.filter(user => user.role === 'student' && !state.sections.some(section => section.id === user.sectionId))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }))
    .map(user => ({ id: user.id, name: user.name, email: user.email }));
  res.json({ students });
});

app.put('/api/admin/students/:id/section', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const sectionId = parseSectionId(req.body.sectionId);
  const state = readState();
  const student = state.users.find(user => user.id === id && user.role === 'student');
  if (!student) return fail(res, 404, 'Student not found.');
  if (!Number.isInteger(sectionId) || !state.sections.some(section => section.id === sectionId)) return fail(res, 400, 'Choose a valid section.');
  student.sectionId = sectionId;
  writeState(state);
  res.json({ ok: true });
});

app.post('/api/student/qr', requireAuth, async (req, res, next) => {
  if (req.session.user.role !== 'student') return fail(res, 403, 'Only student accounts have a student QR code.');
  try {
    const state = readState();
    const user = getUserById(state, req.session.user.id);
    if (!user) return fail(res, 404, 'Student account not found.');
    const token = crypto.randomBytes(32).toString('base64url');
    user.studentQrTokenHash = crypto.createHash('sha256').update(token).digest('hex');
    user.studentQrExpiresAt = Date.now() + 10 * 60 * 1000;
    writeState(state);
    const qrValue = `NSTP-STUDENT:${token}`;
    const image = await QRCode.toDataURL(qrValue, { width: 300, margin: 2, errorCorrectionLevel: 'M' });
    res.json({ image, qrValue, expiresAt: user.studentQrExpiresAt });
  } catch (error) {
    next(error);
  }
});

app.post('/api/admin/attendance/scan', requireAuth, requireAdmin, (req, res) => {
  const qrValue = String(req.body.token || '').trim();
  const sessionId = Number(req.body.sessionId);
  const action = req.body.action;
  const studentToken = qrValue.startsWith('NSTP-STUDENT:') ? qrValue.slice('NSTP-STUDENT:'.length) : '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(studentToken) || !Number.isInteger(sessionId) || !['in', 'out'].includes(action)) {
    return fail(res, 400, 'Scan a valid student QR and choose a session and IN or OUT.');
  }
  const state = readState();
  const tokenHash = crypto.createHash('sha256').update(studentToken).digest('hex');
  const student = state.users.find(user => user.role === 'student' && user.studentQrTokenHash === tokenHash);
  if (!student || student.studentQrExpiresAt <= Date.now()) return fail(res, 410, 'This student QR has expired. Ask the student to generate a new one.');
  const session = state.sessions.find(item => item.id === sessionId);
  if (!session || !session.active) return fail(res, 410, 'Choose an active attendance session.');
  if (session.sectionId && session.sectionId !== student.sectionId) return fail(res, 403, 'This student is not in the section assigned to this session.');
  const existing = state.attendance.find(record => record.sessionId === session.id && record.userId === student.id);
  const now = new Date().toISOString();
  if (action === 'in') {
    if (existing) return fail(res, 409, 'This student has already checked in for this session.');
    state.attendance.push({ id: nextId(state, 'attendance'), sessionId: session.id, userId: student.id, checkIn: now, checkOut: null });
  } else {
    if (!existing) return fail(res, 409, 'This student has not checked in for this session.');
    if (existing.checkOut) return fail(res, 409, 'This student has already checked out for this session.');
    existing.checkOut = now;
  }
  addActivityLog(state, action === 'in' ? 'attendance_checkin' : 'attendance_checkout', `${student.name} was marked ${action === 'in' ? 'present' : 'checked out'} for ${session.title}.`, student.id, student.name);
  writeState(state);
  res.json({ ok: true, action, student: student.name, section: state.sections.find(item => item.id === student.sectionId)?.name || '', session: session.title, timestamp: now });
});

app.get('/api/tasks', requireAuth, (req, res) => {
  const state = readState();
  const tasks = state.tasks.filter(task => req.session.user.role === 'admin' ||
    !task.sectionId || task.sectionId === getUserById(state, req.session.user.id)?.sectionId)
    .sort((a, b) => a.dueAt.localeCompare(b.dueAt))
    .map(task => {
      const section = state.sections.find(item => item.id === task.sectionId);
      const submissions = state.submissions.filter(item => item.taskId === task.id);
      if (req.session.user.role === 'admin') {
        return { ...task, sectionName: section?.name || 'All sections', submissionCount: submissions.length };
      }
      const submission = submissions.find(item => item.userId === req.session.user.id);
      return {
        id: task.id, title: task.title, description: task.description, dueAt: task.dueAt,
        sectionName: section?.name || 'All sections',
        submission: submission ? { id: submission.id, originalName: submission.originalName, submittedAt: submission.submittedAt } : null
      };
    });
  res.json({ tasks });
});

app.post('/api/tasks', requireAuth, requireAdmin, (req, res) => {
  const title = String(req.body.title || '').trim();
  const description = String(req.body.description || '').trim();
  const dueAt = String(req.body.dueAt || '');
  const sectionId = parseSectionId(req.body.sectionId);
  const dueTime = Date.parse(dueAt);
  const state = readState();
  if (title.length < 2 || title.length > 120) return fail(res, 400, 'Task title must be between 2 and 120 characters.');
  if (description.length > 2000) return fail(res, 400, 'Task instructions must be 2,000 characters or fewer.');
  if (!Number.isFinite(dueTime) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(dueAt)) return fail(res, 400, 'Choose a valid task due date and time.');
  if (!Number.isInteger(sectionId)) return fail(res, 400, 'Choose a valid section or all sections.');
  if (sectionId && !state.sections.some(section => section.id === sectionId)) return fail(res, 400, 'Choose a valid section or all sections.');
  const task = {
    id: nextId(state, 'tasks'), title, description, dueAt: new Date(dueTime).toISOString(),
    sectionId, createdBy: req.session.user.id, createdAt: new Date().toISOString()
  };
  state.tasks.push(task);
  addActivityLog(state, 'task_created', `Task created: ${title}.`, req.session.user.id, req.session.user.name);
  writeState(state);
  res.status(201).json({ task });
});

app.get('/api/tasks/:id/submissions', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const state = readState();
  const task = state.tasks.find(item => item.id === id);
  if (!task) return fail(res, 404, 'Task not found.');
  const submissions = state.submissions.filter(item => item.taskId === id).map(item => {
    const user = getUserById(state, item.userId);
    return { id: item.id, studentName: user?.name || 'Unknown student', studentEmail: user?.email || '', originalName: item.originalName, submittedAt: item.submittedAt };
  }).sort((a, b) => a.studentName.localeCompare(b.studentName));
  res.json({ task, submissions });
});

app.get('/api/admin/activity-logs', requireAuth, requireAdmin, (req, res) => {
  const state = readState();
  const logs = state.activityLogs
    .slice()
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 12)
    .map(log => ({
      ...log,
      actorLabel: log.actorName || 'System'
    }));
  res.json({ logs });
});

app.get('/api/admin/backup.zip', requireAuth, requireAdmin, (req, res) => {
  let backupState;
  try {
    const parsed = fs.existsSync(DB_PATH) ? JSON.parse(fs.readFileSync(DB_PATH, 'utf8')) : defaultState;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid state object.');
    if (parsed.nextIds !== undefined && (!parsed.nextIds || typeof parsed.nextIds !== 'object' || Array.isArray(parsed.nextIds))) {
      throw new Error('Invalid ID counters.');
    }
    backupState = {
      ...defaultState,
      ...parsed,
      nextIds: { ...defaultState.nextIds, ...(parsed.nextIds || {}) },
      qrTokens: [],
      passwordResetTokens: []
    };
    for (const key of Object.keys(defaultState).filter(key => key !== 'nextIds')) {
      if (!Array.isArray(backupState[key])) throw new Error(`Invalid ${key} collection.`);
    }
  } catch (error) {
    return fail(res, 500, 'Backup could not be created because the stored data is unreadable.');
  }

  const createdAt = new Date();
  const fileTimestamp = createdAt.toISOString().replace(/[:.]/g, '-');
  const archive = new yazl.ZipFile();
  const addDirectoryFiles = (directory, archiveDirectory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const filePath = path.join(directory, entry.name);
      const archivePath = path.posix.join(archiveDirectory, entry.name);
      if (entry.isDirectory()) addDirectoryFiles(filePath, archivePath);
      else if (entry.isFile()) archive.addFile(filePath, archivePath);
    }
  };
  try {
    archive.addBuffer(Buffer.from(JSON.stringify({
      format: 'nstp-attendance-backup',
      version: 1,
      createdAt: createdAt.toISOString(),
      omittedTransientCollections: ['qrTokens', 'passwordResetTokens'],
      state: backupState
    }, null, 2)), 'backup.json');
    if (fs.existsSync(SUBMISSIONS_DIR)) addDirectoryFiles(SUBMISSIONS_DIR, 'submissions');
    if (fs.existsSync(PROFILE_PICTURES_DIR)) addDirectoryFiles(PROFILE_PICTURES_DIR, 'profile-pictures');
  } catch (error) {
    return fail(res, 500, 'Backup archive could not be prepared.');
  }

  let archiveFailed = false;
  const handleArchiveError = error => {
    if (archiveFailed) return;
    archiveFailed = true;
    console.error('System backup archive failed:', error);
    if (!res.headersSent) {
      res.removeHeader('Content-Disposition');
      return fail(res, 500, 'Backup archive could not be created.');
    }
    res.destroy(error);
  };
  archive.on('error', handleArchiveError);
  archive.outputStream.on('error', handleArchiveError);

  res.status(200).set({
    'Content-Type': 'application/zip',
    'Content-Disposition': `attachment; filename="nstp-backup-${fileTimestamp}.zip"`,
    'Cache-Control': 'private, no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  archive.outputStream.pipe(res);
  archive.end();
});

app.post('/api/tasks/:id/submissions', requireAuth, submissionLimiter, handleSubmissionUpload, (req, res) => {
  if (req.session.user.role !== 'student') return fail(res, 403, 'Only student accounts can submit task files.');
  if (!req.file) return fail(res, 400, 'Choose a PDF file to submit.');
  const id = Number(req.params.id);
  const state = readState();
  const task = state.tasks.find(item => item.id === id);
  if (!task) return fail(res, 404, 'Task not found.');
  const user = getUserById(state, req.session.user.id);
  if (task.sectionId && task.sectionId !== user?.sectionId) return fail(res, 403, 'This task is not assigned to your section.');
  if (!req.file.originalname.toLowerCase().endsWith('.pdf') ||
      (req.file.mimetype !== 'application/pdf' && req.file.mimetype !== 'application/octet-stream') ||
      req.file.size < 5 || req.file.buffer.subarray(0, 5).toString('ascii') !== '%PDF-') {
    return fail(res, 400, 'Upload a valid PDF file.');
  }

  const existing = state.submissions.find(item => item.taskId === id && item.userId === user.id);
  const submissionId = existing?.id || nextId(state, 'submissions');
  const fileName = `${crypto.randomUUID()}.pdf`;
  fs.mkdirSync(SUBMISSIONS_DIR, { recursive: true });
  fs.writeFileSync(path.join(SUBMISSIONS_DIR, fileName), req.file.buffer, { flag: 'wx' });
  if (existing) {
    try { fs.unlinkSync(path.join(SUBMISSIONS_DIR, existing.fileName)); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  const submission = {
    id: submissionId, taskId: id, userId: user.id, fileName,
    originalName: path.basename(req.file.originalname).slice(0, 180),
    submittedAt: new Date().toISOString()
  };
  if (existing) Object.assign(existing, submission);
  else state.submissions.push(submission);
  addActivityLog(state, 'task_submission', `${user.name} submitted a file for ${task.title}.`, user.id, user.name);
  writeState(state);
  res.status(201).json({ submission: { id: submission.id, originalName: submission.originalName, submittedAt: submission.submittedAt } });
});

app.get('/api/submissions/:id/file', requireAuth, (req, res, next) => {
  const state = readState();
  const submission = state.submissions.find(item => item.id === Number(req.params.id));
  if (!submission) return fail(res, 404, 'Submission not found.');
  if (req.session.user.role !== 'admin' && submission.userId !== req.session.user.id) return fail(res, 403, 'You cannot access this submission.');
  const filePath = path.join(SUBMISSIONS_DIR, submission.fileName);
  res.download(filePath, submission.originalName, error => {
    if (error && !res.headersSent) next(error);
  });
});

app.get('/api/sessions', requireAuth, (req, res) => {
  const state = readState();
  const currentUser = getUserById(state, req.session.user.id);
  const visibleSessions = req.session.user.role === 'admin' ? state.sessions : state.sessions.filter(session =>
    !session.sectionId || session.sectionId === currentUser?.sectionId);
  const sessions = visibleSessions.map((session) => {
    const base = cleanSession({ ...session, active: Boolean(session.active) });
    if (req.session.user.role === 'admin') {
      return {
        ...base, sectionName: state.sections.find(section => section.id === session.sectionId)?.name || 'All sections',
        attendees: state.attendance.filter(record => record.sessionId === session.id).length
      };
    }
    const record = state.attendance.find(att => att.sessionId === session.id && att.userId === req.session.user.id);
    return {
      ...base,
      sectionName: state.sections.find(section => section.id === session.sectionId)?.name || 'All sections',
      attendance_id: record ? record.id : null,
      check_in: record ? record.checkIn : null,
      check_out: record ? record.checkOut : null
    };
  }).sort((a, b) => new Date(b.event_date) - new Date(a.event_date));

  res.json({ sessions });
});

function buildAttendanceSummary(state) {
  const now = new Date();
  const today = localDateString(now);
  const weekStartDate = localDateString(new Date(now.getFullYear(), now.getMonth(), now.getDate() - 6));
  const students = state.users.filter(user => user.role === 'student');
  const completedSessions = state.sessions.filter(session => session.event_date <= today);
  const weekSessions = completedSessions.filter(session => session.event_date >= weekStartDate);
  const todaysSessions = state.sessions.filter(session => {
    const startsAt = sessionStartTimestamp(session);
    return session.event_date === today && (startsAt === null || startsAt <= now.getTime());
  });
  const studentRows = students.map(user => {
    const eligibleSessions = completedSessions.filter(session => !session.sectionId || session.sectionId === user.sectionId);
    const attendedSessions = eligibleSessions.filter(session =>
      state.attendance.some(record => record.sessionId === session.id && record.userId === user.id)).length;
    const eligibleCount = eligibleSessions.length;
    const attendanceRate = eligibleCount ? Math.round(attendedSessions / eligibleCount * 100) : null;
    const lowAttendance = eligibleCount > 0 && attendedSessions / eligibleCount < 0.75;
    const weekEligibleSessions = weekSessions.filter(session => !session.sectionId || session.sectionId === user.sectionId);
    const weekAttended = weekEligibleSessions.filter(session =>
      state.attendance.some(record => record.sessionId === session.id && record.userId === user.id)).length;
    const weekEligible = weekEligibleSessions.length;
    const weekAttendanceRate = weekEligible ? Math.round(weekAttended / weekEligible * 100) : null;
    const weekLowAttendance = weekEligible > 0 && weekAttended / weekEligible < 0.75;
    return {
      studentId: user.id,
      sectionId: user.sectionId,
      name: user.name,
      email: user.email,
      section: state.sections.find(section => section.id === user.sectionId)?.name || 'Unassigned',
      attended: attendedSessions,
      eligible: eligibleCount,
      absent: eligibleCount - attendedSessions,
      attendanceRate,
      lowAttendance,
      weekAttended,
      weekEligible,
      weekAttendanceRate,
      weekLowAttendance
    };
  });
  const sessions = completedSessions.map(session => {
    const eligibleStudents = students.filter(user => !session.sectionId || session.sectionId === user.sectionId);
    const present = eligibleStudents.filter(user =>
      state.attendance.some(record => record.sessionId === session.id && record.userId === user.id)).length;
    return {
      id: session.id,
      title: session.title,
      eventDate: session.event_date,
      startTime: session.start_time || null,
      startAt: session.start_at || null,
      section: state.sections.find(section => section.id === session.sectionId)?.name || 'All sections',
      present,
      eligible: eligibleStudents.length,
      attendanceRate: eligibleStudents.length ? Math.round(present / eligibleStudents.length * 100) : null
    };
  }).sort((a, b) => b.eventDate.localeCompare(a.eventDate));
  const todayStudents = new Map();
  const todaySessionRows = todaysSessions.map(session => {
    const eligibleStudents = students.filter(user => !session.sectionId || user.sectionId === session.sectionId);
    let present = 0;
    let late = 0;
    for (const student of eligibleStudents) {
      let status = todayStudents.get(student.id);
      if (!status) {
        status = { onTime: false, late: false };
        todayStudents.set(student.id, status);
      }
      const record = state.attendance.find(item => item.sessionId === session.id && item.userId === student.id);
      if (!record) continue;
      if (isLateForSession(session, record.checkIn)) {
        late++;
        status.late = true;
      } else {
        present++;
        status.onTime = true;
      }
    }
    return {
      id: session.id,
      title: session.title,
      startTime: session.start_time || null,
      startAt: session.start_at || null,
      section: state.sections.find(section => section.id === session.sectionId)?.name || 'All sections',
      present,
      late,
      absent: eligibleStudents.length - present - late,
      eligible: eligibleStudents.length,
      attendanceRate: eligibleStudents.length ? Math.round((present + late) / eligibleStudents.length * 100) : null
    };
  });
  const dailyPresent = [...todayStudents.values()].filter(status => status.onTime).length;
  const dailyLate = [...todayStudents.values()].filter(status => !status.onTime && status.late).length;
  const dailyAbsent = todayStudents.size - dailyPresent - dailyLate;
  const dailyAttended = dailyPresent + dailyLate;
  const eligibleTotal = studentRows.reduce((sum, student) => sum + student.eligible, 0);
  const attendedTotal = studentRows.reduce((sum, student) => sum + student.attended, 0);
  return {
    weekStartDate,
    summary: {
      conductedSessions: completedSessions.length,
      averageRate: eligibleTotal ? Math.round(attendedTotal / eligibleTotal * 100) : null,
      lowAttendanceCount: studentRows.filter(student => student.lowAttendance).length,
      totalStudents: students.length
    },
    today: {
      date: today,
      eligibleStudents: todayStudents.size,
      present: dailyPresent,
      late: dailyLate,
      absent: dailyAbsent,
      attendanceRate: todayStudents.size ? Math.round(dailyAttended / todayStudents.size * 100) : null,
      sessions: todaySessionRows
    },
    students: studentRows.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' })),
    sessions
  };
}

app.get('/api/admin/attendance/summary', requireAuth, requireAdmin, (req, res) => {
  res.json(buildAttendanceSummary(readState()));
});

app.get('/api/admin/attendance/report.csv', requireAuth, requireAdmin, (req, res) => {
  const sectionId = req.query.sectionId === undefined || req.query.sectionId === '' ? null : Number(req.query.sectionId);
  const state = readState();
  if (sectionId !== null && (!Number.isInteger(sectionId) || sectionId <= 0 ||
      !state.sections.some(section => section.id === sectionId))) {
    return fail(res, 400, 'Choose a valid section for the attendance report.');
  }
  const { students } = buildAttendanceSummary(state);
  const rows = sectionId === null ? students : students.filter(student =>
    state.users.find(user => user.id === student.studentId)?.sectionId === sectionId);
  const csvCell = value => {
    let text = String(value ?? '');
    if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  const csv = [
    ['Section', 'Student name', 'Email', 'Sessions attended', 'Eligible sessions', 'Absences', 'Attendance rate'],
    ...rows.map(student => [
      student.section, student.name, student.email, student.attended, student.eligible,
      student.absent, student.attendanceRate === null ? 'N/A' : `${student.attendanceRate}%`
    ])
  ].map(row => row.map(csvCell).join(',')).join('\r\n');
  const suffix = sectionId === null ? 'all-sections' : `section-${sectionId}`;
  res.set({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="nstp-attendance-${suffix}.csv"`,
    'Cache-Control': 'no-store'
  }).send(`\uFEFF${csv}`);
});

app.post('/api/sessions', requireAuth, requireAdmin, (req, res) => {
  const title = String(req.body.title || '').trim();
  const eventDate = String(req.body.eventDate || '').trim();
  const startTime = String(req.body.startTime || '').trim();
  const startAt = String(req.body.startAt || '').trim();
  const location = String(req.body.location || '').trim().slice(0, 120);
  const sectionId = parseSectionId(req.body.sectionId);
  if (title.length < 2 || title.length > 120 || !isValidDateString(eventDate) ||
      !/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime) ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(startAt) ||
      !Number.isFinite(new Date(startAt).getTime())) {
    return fail(res, 400, 'Enter a title, valid event date, and valid start time.');
  }

  const state = readState();
  if (!Number.isInteger(sectionId)) return fail(res, 400, 'Choose a valid section or all sections.');
  if (sectionId && !state.sections.some(section => section.id === sectionId)) return fail(res, 400, 'Choose a valid section or all sections.');
  const session = {
    id: nextId(state, 'sessions'),
    title,
    event_date: eventDate,
    start_time: startTime,
    start_at: startAt,
    location,
    sectionId,
    active: true,
    created_by: req.session.user.id,
    created_at: new Date().toISOString()
  };
  state.sessions.push(session);
  writeState(state);

  res.status(201).json({ session: cleanSession(session) });
});

app.put('/api/sessions/:id', requireAuth, requireAdmin, (req, res) => {
  const state = readState();
  const session = state.sessions.find(item => item.id === Number(req.params.id));
  if (!session) return fail(res, 404, 'Attendance session not found.');

  const title = String(req.body.title ?? session.title).trim();
  const eventDate = String(req.body.eventDate ?? session.event_date).trim();
  const startTime = String(req.body.startTime ?? session.start_time ?? '09:00').trim();
  const requestedStartAt = String(req.body.startAt ?? session.start_at ?? '').trim();
  const location = String(req.body.location ?? session.location).trim().slice(0, 120);
  const active = req.body.active === undefined ? session.active : Boolean(req.body.active);
  const sectionId = parseSectionId(req.body.sectionId === undefined ? session.sectionId : req.body.sectionId);
  if (title.length < 2 || title.length > 120 || !isValidDateString(eventDate) ||
      !/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime) ||
      (requestedStartAt && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(requestedStartAt) ||
      !Number.isFinite(new Date(requestedStartAt).getTime())))) {
    return fail(res, 400, 'Enter a title, valid event date, and valid start time.');
  }
  const startAt = requestedStartAt || new Date(`${eventDate}T${startTime}:00`).toISOString();
  if (!Number.isInteger(sectionId) || (sectionId && !state.sections.some(item => item.id === sectionId))) {
    return fail(res, 400, 'Choose a valid section or all sections.');
  }
  if (sectionId !== (session.sectionId || null) && state.attendance.some(record => record.sessionId === session.id)) {
    return fail(res, 409, 'A session section cannot be changed after attendance has been recorded.');
  }

  session.title = title;
  session.event_date = eventDate;
  session.start_time = startTime;
  session.start_at = startAt;
  session.location = location;
  session.sectionId = sectionId;
  session.active = active;
  writeState(state);

  res.json({ session: cleanSession(session) });
});

app.delete('/api/sessions/:id', requireAuth, requireAdmin, (req, res) => {
  const state = readState();
  const index = state.sessions.findIndex(item => item.id === Number(req.params.id));
  if (index === -1) return fail(res, 404, 'Attendance session not found.');
  state.sessions.splice(index, 1);
  state.attendance = state.attendance.filter(entry => entry.sessionId !== Number(req.params.id));
  state.qrTokens = state.qrTokens.filter(token => token.sessionId !== Number(req.params.id));
  writeState(state);
  res.json({ ok: true });
});

app.get('/api/sessions/:id/attendance', requireAuth, requireAdmin, (req, res) => {
  const state = readState();
  const session = state.sessions.find(item => item.id === Number(req.params.id));
  if (!session) return fail(res, 404, 'Attendance session not found.');
  const students = state.users.filter(user => user.role === 'student' &&
    (!session.sectionId || user.sectionId === session.sectionId));
  const today = localDateString();
  const rows = students.map(user => {
    const record = state.attendance.find(item => item.sessionId === session.id && item.userId === user.id);
    const status = record
      ? isLateForSession(session, record.checkIn) ? 'Late' : 'Present'
      : session.event_date > today ? 'Pending' : 'Absent';
    return {
      id: record?.id || null, session_id: session.id, user_id: user.id,
      check_in: record?.checkIn || null, check_out: record?.checkOut || null,
      name: user.name, email: user.email, status
    };
  }).sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
  res.json({ attendance: rows });
});

app.put('/api/attendance/:id', requireAuth, requireAdmin, (req, res) => {
  const state = readState();
  const record = state.attendance.find(item => item.id === Number(req.params.id));
  if (!record) return fail(res, 404, 'Attendance record not found.');

  const checkIn = req.body.checkIn === undefined ? record.checkIn : String(req.body.checkIn);
  const checkOut = req.body.checkOut === undefined ? record.checkOut : (req.body.checkOut ? String(req.body.checkOut) : null);
  const reason = String(req.body.reason || '').trim();
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d/.test(checkIn) || !Number.isFinite(Date.parse(checkIn)) ||
      (checkOut && (!/^\d{4}-\d\d-\d\dT\d\d:\d\d/.test(checkOut) || !Number.isFinite(Date.parse(checkOut))))) {
    return fail(res, 400, 'Use valid date/time values.');
  }
  if (checkOut && Date.parse(checkOut) < Date.parse(checkIn)) return fail(res, 400, 'Check-out cannot be earlier than check-in.');
  if (reason.length < 3 || reason.length > 500) return fail(res, 400, 'Provide a reason for the correction (3–500 characters).');

  const previous = { checkIn: record.checkIn, checkOut: record.checkOut };
  const student = getUserById(state, record.userId);
  const session = state.sessions.find(item => item.id === record.sessionId);
  record.checkIn = checkIn;
  record.checkOut = checkOut;
  addActivityLog(
    state,
    'attendance_corrected',
    `Attendance corrected for ${student?.name || 'student'} in ${session?.title || 'session'}. Reason: ${reason}. Previous check-in/out: ${previous.checkIn || 'none'} / ${previous.checkOut || 'none'}. New check-in/out: ${checkIn} / ${checkOut || 'none'}.`,
    req.session.user.id,
    req.session.user.name
  );
  writeState(state);
  res.json({ ok: true });
});

app.delete('/api/attendance/:id', requireAuth, requireAdmin, (req, res) => {
  const state = readState();
  const index = state.attendance.findIndex(item => item.id === Number(req.params.id));
  if (index === -1) return fail(res, 404, 'Attendance record not found.');
  const reason = String(req.body.reason || '').trim();
  if (reason.length < 3 || reason.length > 500) return fail(res, 400, 'Provide a reason for removing the record (3–500 characters).');
  const [record] = state.attendance.splice(index, 1);
  const student = getUserById(state, record.userId);
  const session = state.sessions.find(item => item.id === record.sessionId);
  addActivityLog(
    state,
    'attendance_removed',
    `Attendance record removed for ${student?.name || 'student'} in ${session?.title || 'session'}. Reason: ${reason}. Removed check-in/out: ${record.checkIn || 'none'} / ${record.checkOut || 'none'}.`,
    req.session.user.id,
    req.session.user.name
  );
  writeState(state);
  res.json({ ok: true });
});

app.post('/api/sessions/:id/qr', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const state = readState();
    const session = state.sessions.find(item => item.id === Number(req.params.id));
    if (!session) return fail(res, 404, 'Attendance session not found.');
    if (!session.active) return fail(res, 400, 'This session is inactive.');

    const token = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    const expiresAt = now + 10 * 60 * 1000;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    state.qrTokens = state.qrTokens.filter(item => item.expiresAt > now);
    state.qrTokens.push({
      id: nextId(state, 'qrTokens'),
      sessionId: session.id,
      tokenHash,
      expiresAt,
      createdAt: now
    });
    writeState(state);

    const url = `${req.protocol}://${req.get('host')}/?scan=${encodeURIComponent(token)}`;
    const image = await QRCode.toDataURL(url, { width: 300, margin: 2, errorCorrectionLevel: 'M' });
    res.json({ image, url, expiresAt });
  } catch (error) {
    next(error);
  }
});

app.post('/api/attendance/scan', requireAuth, (req, res) => {
  if (req.session.user.role !== 'student') return fail(res, 403, 'Only student accounts can submit attendance.');

  const token = String(req.body.token || '').trim();
  const action = req.body.action;
  if (!token || token.length > 200 || !['in', 'out'].includes(action)) {
    return fail(res, 400, 'Scan a valid attendance QR and choose IN or OUT.');
  }

  const state = readState();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const qr = state.qrTokens.find(item => item.tokenHash === tokenHash);
  if (!qr || qr.expiresAt <= Date.now()) return fail(res, 410, 'This QR code has expired. Ask the administrator for a new one.');

  const session = state.sessions.find(item => item.id === qr.sessionId);
  if (!session || !session.active) return fail(res, 410, 'This attendance session is no longer active.');
  const student = getUserById(state, req.session.user.id);
  if (session.sectionId && session.sectionId !== student?.sectionId) return fail(res, 403, 'This session is assigned to a different section.');

  const existing = state.attendance.find(record => record.sessionId === session.id && record.userId === req.session.user.id);
  const now = new Date().toISOString();

  if (action === 'in') {
    if (existing) return fail(res, 409, 'You have already checked in for this session.');
    state.attendance.push({
      id: nextId(state, 'attendance'),
      sessionId: session.id,
      userId: req.session.user.id,
      checkIn: now,
      checkOut: null
    });
  } else {
    if (!existing) return fail(res, 409, 'Check in before checking out.');
    if (existing.checkOut) return fail(res, 409, 'You have already checked out for this session.');
    existing.checkOut = now;
  }

  writeState(state);
  res.json({ ok: true, action, session: session.title, timestamp: now });
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(ROOT, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Unexpected server error.' });
});

app.listen(PORT, () => console.log(`NSTP Attendance is running at http://localhost:${PORT}`));
