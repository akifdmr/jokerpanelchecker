require('dotenv').config();
const express = require('express');
const path = require('path');
const os = require('os');
const fs = require('fs').promises;
const crypto = require('crypto');
const https = require('https');
const net = require('net');

process.env.PUPPETEER_CACHE_DIR = process.env.PUPPETEER_CACHE_DIR || path.join(__dirname, '.cache', 'puppeteer');

const puppeteer = require('puppeteer');
const { MongoClient } = require('mongodb');
const JSZip = require('jszip');
const ProxyChain = require('proxy-chain');
const { SocksProxyAgent } = require('socks-proxy-agent');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const CHECK_PROGRESS_DELAY_MS = Number(process.env.CHECK_PROGRESS_DELAY_MS || 1000);
const CHECK_PAGE_DELAY_MS = Number(process.env.CHECK_PAGE_DELAY_MS || 1000);
const CHECK_ATTEMPT_DELAY_MS = Number(process.env.CHECK_ATTEMPT_DELAY_MS || 2000);
const PROXY_CHECK_TIMEOUT_MS = Number(process.env.PROXY_CHECK_TIMEOUT_MS || 12000);
const RESULTS_FILE = process.env.RESULTS_FILE || path.join(os.tmpdir(), 'panelcheckers-results.json');
const ENV_ALLOWED_HOSTS = String(process.env.CHECK_ALLOWED_HOSTS || 'localhost,127.0.0.1')
    .split(',')
    .map(host => normalizeHost(host))
    .filter(Boolean);
const CHECK_ALLOWED_ROOT_DOMAINS = String(process.env.CHECK_ALLOWED_ROOT_DOMAINS || '')
    .split(',')
    .map(host => normalizeHost(host))
    .filter(Boolean);
const SESSION_COOKIE = 'panelcheckers_session';
const SESSION_SECRET = process.env.SESSION_SECRET || 'panelcheckers-dev-secret-change-me';
const BROWSER_HEADLESS = process.env.BROWSER_HEADLESS
    ? !['0', 'false', 'no'].includes(String(process.env.BROWSER_HEADLESS).toLowerCase())
    : IS_PRODUCTION ? 'new' : false;
const BROWSER_USER_DATA_ROOT = process.env.BROWSER_USER_DATA_ROOT || path.join(os.tmpdir(), 'panelcheckers-browser-profiles');

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let clients = [];
let db = null;
let mongoStatus = {
    configured: false,
    attempted: false,
    connected: false,
    error: null
};
let dynamicAllowedHosts = new Set();
const userProxyConfigs = new Map();

function normalizeHost(value) {
    const raw = String(value || '').trim().toLowerCase();
    if (!raw) return '';
    try {
        const parsed = new URL(raw.includes('://') ? raw : `https://${raw}`);
        return parsed.hostname.replace(/^www\./, '');
    } catch {
        return raw
            .replace(/^https?:\/\//, '')
            .split('/')[0]
            .split(':')[0]
            .replace(/^www\./, '')
            .replace(/[^a-z0-9.-]/g, '');
    }
}

function getAllowedHosts() {
    return [...new Set([...ENV_ALLOWED_HOSTS, ...dynamicAllowedHosts])].sort();
}

function normalizeUsername(username) {
    return String(username || '').trim().toLowerCase();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256').toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
    if (!storedHash || !storedHash.includes(':')) return false;
    const [salt, hash] = storedHash.split(':');
    const candidate = hashPassword(password, salt).split(':')[1];
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(candidate, 'hex'));
}

function signValue(value) {
    return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function createSessionCookie(user) {
    const payload = Buffer.from(JSON.stringify({
        id: String(user._id),
        username: user.username,
        role: user.role
    })).toString('base64url');
    return `${payload}.${signValue(payload)}`;
}

function parseCookies(req) {
    return String(req.headers.cookie || '')
        .split(';')
        .map(part => part.trim())
        .filter(Boolean)
        .reduce((acc, part) => {
            const eq = part.indexOf('=');
            if (eq === -1) return acc;
            acc[part.slice(0, eq)] = decodeURIComponent(part.slice(eq + 1));
            return acc;
        }, {});
}

function getSessionUser(req) {
    const token = parseCookies(req)[SESSION_COOKIE];
    if (!token || !token.includes('.')) return null;
    const [payload, signature] = token.split('.');
    if (signature !== signValue(payload)) return null;
    try {
        return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    } catch {
        return null;
    }
}

function requireAuth(req, res, next) {
    const user = getSessionUser(req);
    if (!user) return res.status(401).json({ error: 'Giriş gerekli.' });
    req.user = user;
    next();
}

function requireAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') return next();
    return res.status(403).json({ error: 'Admin yetkisi gerekli.' });
}

function safeFileToken(value, fallback = 'anon') {
    return String(value || fallback).replace(/[^a-zA-Z0-9_-]/g, '');
}

function getResultsFile(userId, runId = 'current') {
    const suffix = String(userId || 'anon').replace(/[^a-zA-Z0-9_-]/g, '');
    const runSuffix = safeFileToken(runId, 'current');
    return RESULTS_FILE.replace(/\.json$/i, `-${suffix}-${runSuffix}.json`);
}

function maskPassword(password) {
    const value = String(password || '');
    if (!value) return '';
    if (value.length <= 2) return '*'.repeat(value.length);
    return `${value.slice(0, 1)}${'*'.repeat(Math.max(value.length - 2, 2))}${value.slice(-1)}`;
}

function getDomainFromUrl(value) {
    try {
        return new URL(normalizeUrl(value)).hostname.replace(/^www\./, '').toLowerCase();
    } catch {
        return '';
    }
}

function isAllowedCheckUrl(value) {
    try {
        const url = new URL(normalizeUrl(value));
        return getAllowedHosts().includes(normalizeHost(url.hostname));
    } catch {
        return false;
    }
}

function isLocalAllowedHost(host) {
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

function isHostUnderRoot(host, root) {
    return host === root || host.endsWith(`.${root}`);
}

function validateAllowedHostCandidate(input) {
    const host = normalizeHost(input);
    if (!host) return { ok: false, error: 'Host boş olamaz.' };
    if (!/^(localhost|(\d{1,3}\.){3}\d{1,3}|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)$/.test(host)) {
        return { ok: false, error: 'Geçerli bir host girin. Örnek: login.sirket.com' };
    }
    if (isLocalAllowedHost(host)) return { ok: true, host };
    if (CHECK_ALLOWED_ROOT_DOMAINS.some(root => isHostUnderRoot(host, root))) return { ok: true, host };
    return {
        ok: false,
        error: CHECK_ALLOWED_ROOT_DOMAINS.length
            ? `Host izinli kök domain altında değil. İzinli kökler: ${CHECK_ALLOWED_ROOT_DOMAINS.join(', ')}`
            : 'Şirket domaini eklemek için önce CHECK_ALLOWED_ROOT_DOMAINS env değerini tanımlayın.'
    };
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function isPrivateIp(host) {
    if (!net.isIP(host)) return false;
    if (host === '::1') return true;
    if (host.includes(':')) {
        const normalized = host.toLowerCase();
        return normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe8')
            || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb');
    }
    const parts = host.split('.').map(Number);
    return parts[0] === 10
        || parts[0] === 127
        || (parts[0] === 169 && parts[1] === 254)
        || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
        || (parts[0] === 192 && parts[1] === 168);
}

function parseSocksProxy(input) {
    const raw = String(input || '').trim();
    if (!raw) throw new Error('SOCKS5 proxy connection string gerekli.');

    let parsed;
    try {
        parsed = new URL(raw.includes('://') ? raw : `socks5://${raw}`);
    } catch {
        throw new Error('Geçersiz proxy connection string.');
    }

    if (!['socks5:', 'socks5h:'].includes(parsed.protocol)) {
        throw new Error('Yalnızca socks5:// veya socks5h:// proxy desteklenir.');
    }
    if (!parsed.hostname || !parsed.port) {
        throw new Error('Proxy host ve port içermelidir.');
    }
    if (['localhost', 'localhost.localdomain'].includes(parsed.hostname.toLowerCase()) || isPrivateIp(parsed.hostname)) {
        throw new Error('Yerel veya özel ağ proxy adresleri kabul edilmez.');
    }

    return {
        url: parsed.toString(),
        protocol: parsed.protocol.replace(':', ''),
        host: parsed.hostname,
        port: Number(parsed.port),
        username: decodeURIComponent(parsed.username || ''),
        hasPassword: Boolean(parsed.password)
    };
}

function publicProxyInfo(config, geo = null) {
    return {
        configured: true,
        protocol: config.protocol,
        host: config.host,
        port: config.port,
        username: config.username || '',
        hasPassword: config.hasPassword,
        label: `${config.protocol}://${config.username ? `${config.username}@` : ''}${config.host}:${config.port}`,
        geo
    };
}

async function lookupProxyGeo(proxyUrl) {
    const agent = new SocksProxyAgent(proxyUrl);
    return new Promise((resolve, reject) => {
        const request = https.get('https://ipwho.is/', {
            agent,
            timeout: PROXY_CHECK_TIMEOUT_MS,
            headers: {
                Accept: 'application/json',
                'User-Agent': 'PanelCheckers-ProxyVerifier/1.0'
            }
        }, response => {
            let body = '';
            response.setEncoding('utf8');
            response.on('data', chunk => {
                body += chunk;
                if (body.length > 128 * 1024) request.destroy(new Error('Proxy doğrulama cevabı çok büyük.'));
            });
            response.on('end', () => {
                if (response.statusCode < 200 || response.statusCode >= 300) {
                    reject(new Error(`Konum servisi HTTP ${response.statusCode} döndürdü.`));
                    return;
                }
                try {
                    const data = JSON.parse(body);
                    if (data.success === false || !data.ip) {
                        reject(new Error(data.message || 'Proxy çıkış IP bilgisi alınamadı.'));
                        return;
                    }
                    resolve({
                        ip: data.ip,
                        country: data.country || '',
                        countryCode: data.country_code || '',
                        region: data.region || '',
                        city: data.city || '',
                        postal: data.postal || '',
                        latitude: data.latitude ?? null,
                        longitude: data.longitude ?? null,
                        timezone: data.timezone && data.timezone.id ? data.timezone.id : ''
                    });
                } catch {
                    reject(new Error('Proxy konum servisi geçersiz cevap döndürdü.'));
                }
            });
        });
        request.on('timeout', () => request.destroy(new Error('Proxy bağlantısı zaman aşımına uğradı.')));
        request.on('error', reject);
    });
}

function getBrowserLaunchOptions(runId = 'manual', browserProxyUrl = '') {
    const userDataDir = path.join(BROWSER_USER_DATA_ROOT, safeFileToken(runId, 'manual'));
    const args = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-crash-reporter',
        '--disable-crashpad'
    ];
    if (browserProxyUrl) args.push(`--proxy-server=${browserProxyUrl}`);
    return {
        headless: BROWSER_HEADLESS,
        slowMo: IS_PRODUCTION || BROWSER_HEADLESS ? 0 : 250,
        userDataDir,
        args
    };
}

async function runBrowserSmokeTest(browser) {
    const page = await browser.newPage();
    try {
        await page.goto('data:text/html,<form><input name="username"><input type="password"><button type="submit">Login</button></form>', {
            waitUntil: 'domcontentloaded',
            timeout: 5000
        });
        const hasForm = await page.$('input[name="username"]') && await page.$('input[type="password"]');
        if (!hasForm) throw new Error('Smoke test login form not found');
    } finally {
        await page.close().catch(() => {});
    }
}

async function initializeAuthCollections() {
    if (!db) return;
    const users = db.collection('users');
    await users.createIndex({ username: 1 }, { unique: true });
    await db.collection('check_results').createIndex({ ownerUserId: 1, createdAt: -1 });
    await db.collection('successful_logins').createIndex({ ownerUserId: 1, createdAt: -1 });
    await db.collection('session_logs').createIndex({ createdAt: -1 });
    await db.collection('session_logs').createIndex({ username: 1, createdAt: -1 });
    await db.collection('allowed_hosts').createIndex({ host: 1 }, { unique: true });
    const storedHosts = await db.collection('allowed_hosts').find({}, { projection: { host: 1 } }).toArray();
    dynamicAllowedHosts = new Set(storedHosts.map(item => normalizeHost(item.host)).filter(Boolean));

    const seeds = [];
    if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
        seeds.push({
            username: normalizeUsername(process.env.ADMIN_USERNAME),
            role: 'admin',
            passwordHash: hashPassword(process.env.ADMIN_PASSWORD),
            createdAt: new Date()
        });
    }
    if (process.env.USER_USERNAME && process.env.USER_PASSWORD) {
        seeds.push({
            username: normalizeUsername(process.env.USER_USERNAME),
            role: 'user',
            passwordHash: hashPassword(process.env.USER_PASSWORD),
            createdAt: new Date()
        });
    }

    if (!IS_PRODUCTION && seeds.length === 0) {
        seeds.push(
            { username: 'admin', role: 'admin', passwordHash: hashPassword('admin123'), createdAt: new Date() },
            { username: 'user', role: 'user', passwordHash: hashPassword('user123'), createdAt: new Date() }
        );
        console.log('⚠ Dev kullanıcıları oluşturuldu: admin/admin123 ve user/user123');
    }

    if (seeds.length > 0) {
        for (const seed of seeds) {
            await users.updateOne(
                { username: seed.username },
                {
                    $set: {
                        role: seed.role,
                        passwordHash: seed.passwordHash,
                        updatedAt: new Date()
                    },
                    $setOnInsert: {
                        createdAt: seed.createdAt
                    }
                },
                { upsert: true }
            );
        }
        console.log(`✅ ${seeds.length} auth kullanıcısı env değerlerine göre hazırlandı`);
    } else {
        const existingUsers = await users.countDocuments();
        console.log(`✅ Auth kullanıcıları MongoDB'den okunacak. Kayıtlı kullanıcı: ${existingUsers}`);
    }
}

function getRequestIp(req) {
    return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
        .split(',')[0]
        .trim();
}

async function saveSessionLog(req, event, details = {}) {
    if (!db) return;
    try {
        await db.collection('session_logs').insertOne({
            event,
            userId: details.userId || null,
            username: normalizeUsername(details.username),
            role: details.role || null,
            success: event === 'login_success' || event === 'logout',
            reason: details.reason || '',
            ip: getRequestIp(req),
            userAgent: String(req.headers['user-agent'] || ''),
            createdAt: new Date()
        });
    } catch (err) {
        console.error('Session log kayıt hatası:', err.message);
    }
}

// ------------------ MONGODB BAĞLANTISI (X509 SERTİFİKA DESTEKLİ) ------------------
async function connectMongo() {
    try {
        const uri = process.env.MONGODB_CONNECTIONSTRING || process.env.DATABASE_URL;
        mongoStatus = {
            configured: Boolean(uri),
            attempted: Boolean(uri),
            connected: false,
            error: null
        };
        if (!uri) {
            console.log('⚠ MongoDB connection string bulunamadı, veritabanı kaydı yapılmayacak.');
            mongoStatus.error = 'MongoDB connection string missing';
            return;
        }

        console.log('MongoDB bağlantısı başlatılıyor...');
        let options = {};

        if (uri.includes('MONGODB-X509')) {
            console.log('🔐 X509 authentication modu aktif, sertifika ile bağlanılıyor...');
            const certPath = process.env.MONGODB_CERT_PATH;
            if (certPath && (await fs.access(certPath).then(() => true).catch(() => false))) {
                options = {
                    tlsCertificateKeyFile: certPath,
                    tlsAllowInvalidCertificates: false
                };
                console.log(`🔐 X509 sertifika dosyası kullanılıyor: ${certPath}`);
            } else {
                console.log('⚠ X509 sertifika dosyası bulunamadı. Sadece connection string deneniyor...');
            }
        } else if (process.env.MONGODB_USERNAME && process.env.MONGODB_PASSWORD) {
            options = {
                auth: { username: process.env.MONGODB_USERNAME, password: process.env.MONGODB_PASSWORD }
            };
        }

        const client = new MongoClient(uri, {
            ...options,
            serverSelectionTimeoutMS: 15000
        });
        await client.connect();
        db = client.db();
        mongoStatus.connected = true;
        await initializeAuthCollections();
        console.log('✅ MongoDB bağlantısı başarılı');
        return client;
    } catch (err) {
        console.error('❌ MongoDB bağlantı hatası:', err.message);
        if (err.message.includes('certificate validation failed')) {
            console.error('X509 sertifika hatası. Lütfen geçerli bir sertifika dosyası sağlayın (MONGODB_CERT_PATH) veya farklı bir auth mekanizması kullanın.');
        }
        db = null;
        mongoStatus.connected = false;
        mongoStatus.error = err.message;
        return null;
    }
}

// ------------------ LOG + SSE ------------------
function canReceiveLog(client, ownerUserId) {
    if (!ownerUserId) return true;
    return client.user.role === 'admin' || client.user.id === ownerUserId;
}

function sendLog(msg, type = 'info', ownerUserId = null) {
    const logEntry = { timestamp: new Date().toISOString(), message: msg, type, ownerUserId };
    clients = clients.filter(c => !c.res.destroyed);
    clients.filter(c => canReceiveLog(c, ownerUserId)).forEach(c => c.res.write(`data: ${JSON.stringify(logEntry)}\n\n`));
    console.log(msg);
}

app.get('/api/log-stream', requireAuth, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    clients.push({ res, user: req.user });
    req.on('close', () => {
        clients = clients.filter(c => c.res !== res);
    });
});

app.get('/health', (req, res) => {
    res.json({
        ok: true,
        service: 'panelcheckers',
        db: db ? 'connected' : 'disabled',
        auth: db ? 'enabled' : 'disabled',
        checker: {
            allowedHosts: getAllowedHosts(),
            envAllowedHosts: ENV_ALLOWED_HOSTS,
            dynamicAllowedHosts: [...dynamicAllowedHosts].sort(),
            allowedRootDomains: CHECK_ALLOWED_ROOT_DOMAINS,
            progressDelayMs: CHECK_PROGRESS_DELAY_MS,
            pageDelayMs: CHECK_PAGE_DELAY_MS,
            attemptDelayMs: CHECK_ATTEMPT_DELAY_MS
        },
        mongo: {
            configured: mongoStatus.configured,
            attempted: mongoStatus.attempted,
            connected: mongoStatus.connected,
            error: mongoStatus.error,
            env: {
                DATABASE_URL: Boolean(process.env.DATABASE_URL),
                MONGODB_CONNECTIONSTRING: Boolean(process.env.MONGODB_CONNECTIONSTRING),
                MONGODB_USERNAME: Boolean(process.env.MONGODB_USERNAME),
                MONGODB_PASSWORD: Boolean(process.env.MONGODB_PASSWORD)
            }
        },
        uptime: process.uptime()
    });
});

app.get('/demo-login', (req, res) => {
    res.type('html').send(`<!doctype html>
<html>
<head>
  <title>Demo Login</title>
  <style>
    body { font-family: system-ui; background: #f3f5f8; margin: 0; display: grid; place-items: center; min-height: 100vh; }
    main { width: min(420px, calc(100vw - 32px)); background: white; border: 1px solid #d9e1ec; border-radius: 8px; padding: 24px; }
    label { display: block; font-weight: 700; margin-top: 12px; }
    input, button { width: 100%; margin-top: 8px; padding: 12px; font: inherit; }
    button { background: #1e466e; color: white; border: 0; border-radius: 6px; cursor: pointer; }
    #message { margin-top: 14px; font-weight: 700; }
  </style>
</head>
<body>
  <main>
    <h1>Demo Login</h1>
    <form id="loginForm">
      <label>Username<input name="username" id="username" autocomplete="username"></label>
      <label>Password<input name="password" id="password" type="password" autocomplete="current-password"></label>
      <button type="submit">Login</button>
      <div id="message"></div>
    </form>
  </main>
  <script>
    document.getElementById('loginForm').addEventListener('submit', event => {
      event.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const message = document.getElementById('message');
      if (username === 'demo' && password === 'demo123') {
        history.pushState({}, '', '/demo-dashboard');
        document.body.innerHTML = '<main><h1>Dashboard</h1><p>Welcome demo account without MFA</p></main>';
      } else if (username === 'mfa' && password === 'mfa123') {
        history.pushState({}, '', '/demo-mfa');
        document.body.innerHTML = '<main><h1>MFA_REQUIRED</h1><p>Password accepted. Two-factor verification required before account access.</p></main>';
      } else {
        message.textContent = 'Invalid username or password';
      }
    });
  </script>
</body>
</html>`);
});

app.post('/api/auth/login', async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok, giriş yapılamaz.' });
        const username = normalizeUsername(req.body && req.body.username);
        const password = String((req.body && req.body.password) || '');
        if (!username || !password) {
            await saveSessionLog(req, 'login_failed', { username, reason: 'missing_credentials' });
            return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli.' });
        }

        const user = await db.collection('users').findOne({ username });
        if (!user || !verifyPassword(password, user.passwordHash)) {
            await saveSessionLog(req, 'login_failed', { username, reason: 'invalid_credentials' });
            return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });
        }

        const cookie = createSessionCookie(user);
        const secure = IS_PRODUCTION ? '; Secure' : '';
        res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(cookie)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${secure}`);
        await saveSessionLog(req, 'login_success', {
            userId: String(user._id),
            username: user.username,
            role: user.role
        });
        res.json({ user: { id: String(user._id), username: user.username, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/logout', async (req, res) => {
    const user = getSessionUser(req);
    if (user) {
        await saveSessionLog(req, 'logout', {
            userId: user.id,
            username: user.username,
            role: user.role
        });
    }
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
    res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({ user: req.user });
});

// ------------------ URL DÜZELTME ------------------
function normalizeUrl(url) {
    url = url.trim();
    if (url.startsWith('//')) url = 'https:' + url;
    if (!url.startsWith('http')) url = 'https://' + url;
    return url;
}

// ------------------ GELİŞMİŞ PARSER ------------------
function parseCredentialLine(line) {
    line = line.trim();
    if (!line) return null;
    if (line.startsWith('###')) return null;

    let url = null;
    let username = null;
    let password = null;

    if (line.includes('://')) {
        const lastColon = line.lastIndexOf(':');
        const secondLastColon = lastColon > -1 ? line.lastIndexOf(':', lastColon - 1) : -1;
        if (secondLastColon === -1) return null;
        url = line.substring(0, secondLastColon);
        username = line.substring(secondLastColon + 1, lastColon);
        password = line.substring(lastColon + 1);
    } else {
        const colonIndex = line.indexOf(':');
        if (colonIndex !== -1) {
            username = line.substring(0, colonIndex);
            password = line.substring(colonIndex + 1);
        } else {
            username = line;
            password = '';
        }
    }
    // Kullanıcı adı boş gelirse geçersiz say
    if (!username || username.trim() === '') {
        return null;
    }
    return { url, username, password };
}

function extractLabeledValue(line, labels) {
    const normalized = String(line || '').trim();
    for (const label of labels) {
        const match = normalized.match(new RegExp(`^[^\\p{L}\\p{N}]*${label}\\s*:\\s*(.+)$`, 'iu'));
        if (match) return match[1].trim();
    }
    return '';
}

function parseCredentialText(credsText) {
    const lines = String(credsText || '').split(/\r?\n/);
    const parsed = [];
    let block = {};

    const flushBlock = () => {
        if (block.url || block.username || block.password) {
            if (block.url && block.username) {
                parsed.push({
                    url: block.url,
                    username: block.username,
                    password: block.password || ''
                });
            }
            block = {};
        }
    };

    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line || line.startsWith('###')) {
            if (!line) flushBlock();
            continue;
        }

        const password = extractLabeledValue(line, ['şifre', 'sifre', 'password', 'parola']);
        const username = extractLabeledValue(line, ['nick', 'kullanıcı', 'kullanici', 'username', 'user']);
        const url = extractLabeledValue(line, ['bağlantı', 'baglanti', 'url', 'link']);

        if (password) {
            if (block.password && (block.url || block.username)) flushBlock();
            block.password = password;
            continue;
        }
        if (username) {
            block.username = username;
            continue;
        }
        if (url) {
            block.url = url;
            if (block.username) flushBlock();
            continue;
        }

        flushBlock();
        const singleLine = parseCredentialLine(line);
        if (singleLine && singleLine.url && singleLine.username) parsed.push(singleLine);
    }

    flushBlock();
    return parsed;
}

function buildStoredResult(result, owner) {
    return {
        ownerUserId: owner.id,
        ownerUsername: owner.username,
        ownerRole: owner.role,
        url: result.baseUrl,
        domain: getDomainFromUrl(result.baseUrl),
        username: result.username,
        passwordMasked: maskPassword(result.password),
        passwordLength: String(result.password || '').length,
        status: result.status || (result.success ? 'success' : 'fail'),
        success: result.success === true,
        message: result.message || '',
        checkedAt: result.timestamp ? new Date(result.timestamp) : new Date(),
        createdAt: new Date()
    };
}

async function saveCheckResult(result, owner) {
    if (!db) return;
    try {
        await db.collection('check_results').insertOne(buildStoredResult(result, owner));
    } catch (err) {
        console.error('Check sonucu kayıt hatası:', err);
        sendLog(`❌ Check sonucu kayıt hatası: ${err.message}`, 'error', owner.id);
    }
}

// ------------------ BAŞARILI GİRİŞİ MONGODB'YE KAYDET ------------------
async function saveSuccessfulLogin(result, owner) {
    if (!db) return;
    try {
        const collection = db.collection('successful_logins');
        await collection.insertOne(buildStoredResult(result, owner));
        sendLog(`💾 Başarılı giriş MongoDB'ye kaydedildi: ${result.username} @ ${result.baseUrl}`, 'success', owner.id);
    } catch (err) {
        console.error('MongoDB kayıt hatası:', err);
        sendLog(`❌ MongoDB kayıt hatası: ${err.message}`, 'error', owner.id);
    }
}

// ------------------ İZOLE SESSION İLE TEST (DAHA YAVAŞ, GÖRÜNÜR) ------------------
async function runAllTests(testItems, owner, runId, proxyConfig = null) {
    const resultsFile = getResultsFile(owner.id, runId);
    const results = testItems.map(item => ({
        baseUrl: item.baseUrl,
        username: item.username,
        password: item.password,
        status: 'queued',
        success: null,
        message: 'SIRADA',
        timestamp: new Date().toISOString()
    }));
    await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));

    const total = testItems.length;
    sendLog(`🚀 BAŞLANGIÇ – ${total} test (her kullanıcı için ayrı izole session)`, 'info', owner.id);
    sendLog(IS_PRODUCTION ? '🌐 Render ortamında browser headless çalışır, pencere açılmaz.' : '🪟 Lokal ortamda browser penceresi açılıyor.', 'info', owner.id);
    sendLog('🧭 Browser motoru başlatılıyor...', 'info', owner.id);

    let browser = null;
    let browserProxyUrl = '';
    try {
        if (proxyConfig) {
            browserProxyUrl = await ProxyChain.anonymizeProxy(proxyConfig.url);
            sendLog(`🌍 SOCKS5 proxy aktif: ${proxyConfig.geo.ip} / ${proxyConfig.geo.country} ${proxyConfig.geo.city}`.trim(), 'success', owner.id);
        }
        const launchOptions = getBrowserLaunchOptions(runId, browserProxyUrl);
        sendLog(`🧩 Browser ayarı: headless=${String(launchOptions.headless)}, profile=${launchOptions.userDataDir}`, 'info', owner.id);
        browser = await puppeteer.launch(launchOptions);
        sendLog('✅ Browser motoru hazır.', 'success', owner.id);
        await runBrowserSmokeTest(browser);
        sendLog('✅ Browser smoke test geçti, gerçek sıraya geçiliyor.', 'success', owner.id);
    } catch (err) {
        const message = `BROWSER_START_FAILED: ${err.message}`;
        sendLog(`❌ ${message}`, 'error', owner.id);
        const failedAt = new Date().toISOString();
        for (const result of results) {
            result.status = 'error';
            result.success = null;
            result.message = message;
            result.timestamp = failedAt;
            await saveCheckResult(result, owner);
        }
        await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));
        sendLog(`🏁 BİTİŞ – Browser başlatılamadığı için ${total} test çalıştırılamadı.`, 'error', owner.id);
        if (browser) await browser.close().catch(() => {});
        if (browserProxyUrl) await ProxyChain.closeAnonymizedProxy(browserProxyUrl, true).catch(() => {});
        return results;
    }

    for (let i = 0; i < total; i++) {
        const { baseUrl, username, password } = testItems[i];
        sendLog(`📌 Test ${i+1}/${total}: ${username} @ ${baseUrl}`, 'info', owner.id);
        sendLog(`🧪 Yeni izole session açılıyor: ${username}`, 'info', owner.id);

        const result = results[i];
        result.status = 'running';
        result.success = null;
        result.message = 'ÇALIŞIYOR';
        result.timestamp = new Date().toISOString();
        await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));
        await delay(CHECK_PROGRESS_DELAY_MS);

        let context = null;
        let page = null;
        try {
            context = await browser.createBrowserContext();
            page = await context.newPage();
            const url = normalizeUrl(baseUrl);
            if (!isAllowedCheckUrl(url)) {
                throw new Error(`CHECK_BLOCKED_HOST: ${new URL(url).hostname} izinli host listesinde yok`);
            }
            await page.goto(url, { waitUntil: 'networkidle2', timeout: 20000 });
            await delay(CHECK_PROGRESS_DELAY_MS);

            let userInput = await page.$('input[type="text"], input[name="username"], input[name="email"], input[name="user"], input[id*="user"], input[id*="email"], input[id="userid"]');
            let passInput = await page.$('input[type="password"]');
            let submitBtn = await page.$('button[type="submit"], input[type="submit"], form button');

            if (!userInput || !passInput || !submitBtn) {
                throw new Error('Login form not found');
            }

            await userInput.click({ clickCount: 3 });
            await userInput.type(username);
            await delay(CHECK_PROGRESS_DELAY_MS);
            await passInput.type(password);
            await delay(CHECK_PROGRESS_DELAY_MS);
            await submitBtn.click();

            await delay(CHECK_PAGE_DELAY_MS);
            const finalUrl = page.url();
            const visibleText = await page.evaluate(() => document.body ? document.body.innerText : '').catch(() => '');

            let success = false;
            const lowerText = visibleText.toLowerCase();
            if (lowerText.includes('mfa_required') || lowerText.includes('two-factor') || lowerText.includes('2fa')) {
                result.success = null;
                result.status = 'mfa_required';
                result.message = 'MFA REQUIRED - PASSWORD CORRECT';
                sendLog(`🛡 2FA GEREKLİ ${username}`, 'info', owner.id);
                await saveCheckResult(result, owner);
                await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));
                continue;
            }

            if (lowerText.includes('invalid') || lowerText.includes('wrong') ||
                lowerText.includes('error') || lowerText.includes('failed') ||
                lowerText.includes('incorrect')) {
                success = false;
            }
            else if (finalUrl !== url && !finalUrl.includes('login') && !finalUrl.includes('signin')) {
                success = true;
            }
            else if (lowerText.includes('dashboard') || lowerText.includes('welcome') || lowerText.includes('account')) {
                success = true;
            }
            else {
                success = false;
            }

            result.success = success;
            result.status = success ? 'success' : 'fail';
            result.message = success ? 'LOGIN OK' : 'LOGIN FAIL';
            sendLog(success ? `✅ BAŞARILI ${username}` : `❌ BAŞARISIZ ${username}`, success ? 'success' : 'fail', owner.id);

            if (success) {
                await saveSuccessfulLogin(result, owner);
            }

        } catch (err) {
            result.status = String(err.message || '').startsWith('CHECK_BLOCKED_HOST') ? 'blocked' : 'error';
            result.success = null;
            result.message = err.message;
            sendLog(`⚠ HATA ${username}: ${err.message}`, 'error', owner.id);
        } finally {
            if (page) {
                await page.close().catch(() => {});
            }
            if (context) {
                await context.close().catch(() => {});
            }
            sendLog(`🧹 Session kapatıldı: ${username}`, 'info', owner.id);
        }

        await saveCheckResult(result, owner);
        await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));
        if (i < total - 1) {
            sendLog(`⏱ Sonraki deneme için ${CHECK_ATTEMPT_DELAY_MS / 1000} saniye bekleniyor.`, 'info', owner.id);
            await delay(CHECK_ATTEMPT_DELAY_MS);
        }
    }

    await browser.close();
    if (browserProxyUrl) await ProxyChain.closeAnonymizedProxy(browserProxyUrl, true).catch(() => {});
    const okCount = results.filter(x => x.status === 'success').length;
    const failCount = results.filter(x => x.status === 'fail').length;
    const mfaCount = results.filter(x => x.status === 'mfa_required').length;
    const errorCount = results.filter(x => x.status === 'error' || x.status === 'blocked').length;
    sendLog(`🏁 BİTİŞ – Başarılı: ${okCount} / Başarısız: ${failCount} / 2FA gerekli: ${mfaCount} / Çalıştırılamadı: ${errorCount}`, 'info', owner.id);
    return results;
}

// ------------------ API ------------------
app.post('/api/start', requireAuth, async (req, res) => {
    try {
        let { credsText } = req.body;
        credsText = credsText || '';

        const parsedCreds = parseCredentialText(credsText);

        const testItems = parsedCreds.map(cred => ({
            baseUrl: cred.url,
            username: cred.username,
            password: cred.password || ''
        }));

        if (testItems.length === 0) {
            return res.status(400).json({ error: 'Geçerli test verisi yok. Format: url:user:pass' });
        }

        const blockedHosts = [...new Set(testItems
            .filter(item => !isAllowedCheckUrl(item.baseUrl))
            .map(item => {
                try {
                    return new URL(normalizeUrl(item.baseUrl)).hostname.toLowerCase();
                } catch {
                    return item.baseUrl;
                }
            }))];

        if (blockedHosts.length > 0) {
            return res.status(400).json({
                error: `İzinli olmayan host bulundu: ${blockedHosts.join(', ')}. Test için CHECK_ALLOWED_HOSTS env değerine sadece yetkili QA hostlarını ekleyin.`,
                allowedHosts: getAllowedHosts()
            });
        }

        const proxyConfig = userProxyConfigs.get(req.user.id) || null;
        const runId = crypto.randomUUID();
        res.json({ message: 'Test başladı', total: testItems.length, runId });
        runAllTests(testItems, req.user, runId, proxyConfig).catch(err => {
            console.error('Test runner fatal error:', err);
            sendLog(`❌ Test çalıştırıcı durdu: ${err.message}`, 'error', req.user.id);
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/proxy', requireAuth, (req, res) => {
    const config = userProxyConfigs.get(req.user.id);
    res.json(config ? publicProxyInfo(config, config.geo) : { configured: false });
});

app.post('/api/proxy', requireAuth, async (req, res) => {
    try {
        const parsed = parseSocksProxy(req.body && req.body.connectionString);
        const geo = await lookupProxyGeo(parsed.url);
        const config = {
            ...parsed,
            geo,
            verifiedAt: new Date().toISOString()
        };
        userProxyConfigs.set(req.user.id, config);
        sendLog(`🌍 Proxy doğrulandı: ${geo.ip} / ${geo.country} ${geo.city}`.trim(), 'success', req.user.id);
        res.json({ ok: true, proxy: publicProxyInfo(config, geo) });
    } catch (err) {
        userProxyConfigs.delete(req.user.id);
        sendLog(`❌ Proxy eklenemedi: ${err.message}`, 'error', req.user.id);
        res.status(400).json({ error: `Proxy eklenemedi: ${err.message}` });
    }
});

app.delete('/api/proxy', requireAuth, (req, res) => {
    userProxyConfigs.delete(req.user.id);
    res.json({ ok: true });
});

app.get('/api/results', requireAuth, async (req, res) => {
    try {
        const runId = req.query.runId;
        if (!runId) return res.json([]);
        const data = await fs.readFile(getResultsFile(req.user.id, runId), 'utf8');
        res.json(JSON.parse(data));
    } catch {
        res.json([]);
    }
});

app.get('/api/download', requireAuth, async (req, res) => {
    try {
        const runId = req.query.runId;
        if (!runId) return res.status(400).send('Run ID yok');
        const data = JSON.parse(await fs.readFile(getResultsFile(req.user.id, runId), 'utf8'));
        const success = data.filter(x => x.status === 'success' || x.success === true);
        const fail = data.filter(x => x.status === 'fail' || x.success === false);
        const error = data.filter(x => x.status === 'error' || x.status === 'blocked');
        let output = '✅ BAŞARILI\n\n';
        success.forEach(x => output += `${x.baseUrl}:${x.username}:${x.password}\n`);
        output += '\n❌ BAŞARISIZ\n\n';
        fail.forEach(x => output += `${x.baseUrl}:${x.username}:${x.password}\n`);
        output += '\n⚠ ÇALIŞTIRILAMADI / ENGELLENDİ\n\n';
        error.forEach(x => output += `${x.baseUrl}:${x.username}:${x.password} # ${x.message || x.status}\n`);
        res.setHeader('Content-Disposition', 'attachment; filename=result.txt');
        res.send(output);
    } catch {
        res.status(500).send('Sonuç dosyası yok');
    }
});

function safeDomainFilename(domain) {
    return String(domain || 'domainsiz')
        .toLowerCase()
        .replace(/^www\./, '')
        .replace(/[^a-z0-9.-]+/g, '_')
        .replace(/^_+|_+$/g, '') || 'domainsiz';
}

app.post('/api/group-download', requireAuth, async (req, res) => {
    try {
        const groups = req.body && req.body.groups;
        if (!Array.isArray(groups) || groups.length === 0) {
            return res.status(400).json({ error: 'Gruplanacak veri yok.' });
        }

        const zip = new JSZip();
        let fileCount = 0;
        for (const group of groups) {
            const domain = safeDomainFilename(group.domain);
            const lines = Array.isArray(group.lines)
                ? group.lines.map(line => String(line || '').trim()).filter(Boolean)
                : [];
            if (!lines.length) continue;
            zip.file(`${domain}.txt`, lines.join('\n') + '\n');
            fileCount += 1;
        }

        if (fileCount === 0) {
            return res.status(400).json({ error: 'Gruplanacak satır yok.' });
        }

        const buffer = await zip.generateAsync({ type: 'nodebuffer' });
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', 'attachment; filename=domain-bazli-listeler.zip');
        res.send(buffer);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

async function historyQueryForUser(req, onlySuccessful = false) {
    if (!db) return [];
    const collection = db.collection(onlySuccessful ? 'successful_logins' : 'check_results');
    const query = {};
    if (req.user.role !== 'admin') query.ownerUserId = req.user.id;
    return collection.find(query, {
        projection: {
            passwordLength: 0
        }
    }).sort({ createdAt: -1 }).limit(500).toArray();
}

app.get('/api/history/checks', requireAuth, async (req, res) => {
    try {
        res.json(await historyQueryForUser(req, false));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/history/successful', requireAuth, async (req, res) => {
    try {
        res.json(await historyQueryForUser(req, true));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        if (!db) return res.json([]);
        const users = await db.collection('users').find({}, {
            projection: { passwordHash: 0 }
        }).sort({ username: 1 }).toArray();
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/session-logs', requireAuth, requireAdmin, async (req, res) => {
    try {
        if (!db) return res.json([]);
        const logs = await db.collection('session_logs')
            .find({})
            .sort({ createdAt: -1 })
            .limit(500)
            .toArray();
        res.json(logs);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/allowed-hosts', requireAuth, requireAdmin, async (req, res) => {
    res.json({
        hosts: getAllowedHosts(),
        envHosts: ENV_ALLOWED_HOSTS,
        dynamicHosts: [...dynamicAllowedHosts].sort(),
        rootDomains: CHECK_ALLOWED_ROOT_DOMAINS,
        persistence: db ? 'mongodb' : 'memory'
    });
});

app.post('/api/admin/allowed-hosts', requireAuth, requireAdmin, async (req, res) => {
    try {
        const validation = validateAllowedHostCandidate(req.body && req.body.host);
        if (!validation.ok) return res.status(400).json({ error: validation.error });

        const host = validation.host;
        dynamicAllowedHosts.add(host);
        if (db) {
            await db.collection('allowed_hosts').updateOne(
                { host },
                {
                    $set: {
                        host,
                        updatedAt: new Date(),
                        updatedBy: req.user.username
                    },
                    $setOnInsert: {
                        createdAt: new Date(),
                        createdBy: req.user.username
                    }
                },
                { upsert: true }
            );
        }
        res.json({ ok: true, host, hosts: getAllowedHosts() });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/allowed-hosts/:host', requireAuth, requireAdmin, async (req, res) => {
    try {
        const host = normalizeHost(req.params.host);
        if (ENV_ALLOWED_HOSTS.includes(host)) {
            return res.status(400).json({ error: 'Env ile gelen host panelden silinemez.' });
        }
        dynamicAllowedHosts.delete(host);
        if (db) await db.collection('allowed_hosts').deleteOne({ host });
        res.json({ ok: true, host, hosts: getAllowedHosts() });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/results', requireAuth, async (req, res) => {
    try {
        const runId = req.query.runId;
        if (runId) {
            await fs.writeFile(getResultsFile(req.user.id, runId), '[]');
        }
        res.json({ ok: true });
    } catch {
        res.status(500).json({ error: 'Silme hatası' });
    }
});

// ------------------ SERVER BAŞLATMA ------------------
(async () => {
    await connectMongo();
    const server = app.listen(PORT, HOST, () => console.log(`✅ Sunucu çalışıyor: http://${HOST}:${PORT}`));
    server.on('error', (err) => {
        console.error(`❌ Sunucu başlatılamadı (${HOST}:${PORT}):`, err.message);
        process.exit(1);
    });
})();
