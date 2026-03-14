/* ============================================
   CyberShield SOC — Hardened Backend Server
   Security controls: Helmet, CSP, rate limiting,
   SSRF protection, input validation, audit logging,
   CORS lockdown, request size limits
   ============================================ */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Trust proxy for Render / load balancers
app.set('trust proxy', 1);

// ============================================
// 1. SECURITY MIDDLEWARE STACK
// ============================================

// --- Helmet: Secure HTTP headers ---
// Sets X-Content-Type-Options, X-Frame-Options, HSTS, etc.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "https://raw.githubusercontent.com"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            objectSrc: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false, // Allow fonts CDN
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// --- CORS: Lock down to same-origin (no wildcard) ---
app.use(cors({
    origin: IS_PROD ? process.env.ALLOWED_ORIGIN || false : true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
    credentials: false,
    maxAge: 600 // Cache preflight for 10 min
}));

// --- Request body size limits (prevent payload abuse) ---
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// --- Global rate limiter: 100 requests per minute per IP ---
const globalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please wait before trying again.' }
});
app.use(globalLimiter);

// --- Strict API rate limiter: 20 requests per minute for proxy routes ---
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'API rate limit exceeded. Max 20 requests/minute.' }
});

// --- Additional security headers not covered by Helmet ---
app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.removeHeader('X-Powered-By');
    next();
});

// ============================================
// 2. AUDIT LOGGING
// ============================================

function auditLog(req, action, details = '') {
    const entry = {
        timestamp: new Date().toISOString(),
        ip: req.ip || req.socket.remoteAddress,
        method: req.method,
        path: req.path,
        action,
        details,
        userAgent: (req.headers['user-agent'] || '').substring(0, 200)
    };
    // In production, send to SIEM / file logger — console for now
    console.log(`[AUDIT] ${entry.timestamp} | ${entry.ip} | ${entry.method} ${entry.path} | ${action} | ${details}`);
}

// ============================================
// 3. INPUT VALIDATION & SSRF PROTECTION
// ============================================

// Validate IP address (IPv4 only, block private/internal ranges)
function isValidPublicIP(ip) {
    const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = ip.match(ipv4);
    if (!match) return false;

    const octets = [parseInt(match[1]), parseInt(match[2]), parseInt(match[3]), parseInt(match[4])];
    if (octets.some(o => o > 255)) return false;

    // Block private, loopback, link-local, and metadata ranges (SSRF protection)
    const [a, b] = octets;
    if (a === 10) return false;                            // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return false;     // 172.16.0.0/12
    if (a === 192 && b === 168) return false;               // 192.168.0.0/16
    if (a === 127) return false;                            // 127.0.0.0/8 (loopback)
    if (a === 169 && b === 254) return false;               // 169.254.0.0/16 (link-local/metadata)
    if (a === 0) return false;                              // 0.0.0.0/8
    if (a >= 224) return false;                             // Multicast & reserved

    return true;
}

// Validate domain name (block internal hostnames)
function isValidDomain(domain) {
    if (!domain || domain.length > 253) return false;
    // Must look like a domain with a TLD
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(domain)) return false;
    // Block common internal hostnames
    const blocked = ['localhost', 'internal', 'metadata', 'kubernetes', '.local', '.internal'];
    if (blocked.some(b => domain.toLowerCase().includes(b))) return false;
    return true;
}

// Validate hash (MD5, SHA1, SHA256 only)
function isValidHash(hash) {
    return /^[a-fA-F0-9]{32}$/.test(hash) ||  // MD5
           /^[a-fA-F0-9]{40}$/.test(hash) ||  // SHA1
           /^[a-fA-F0-9]{64}$/.test(hash);    // SHA256
}

// Validate URL (block SSRF targets)
function isValidExternalURL(url) {
    try {
        const parsed = new URL(url);
        if (!['http:', 'https:'].includes(parsed.protocol)) return false;
        // Block internal/private hostnames
        const host = parsed.hostname.toLowerCase();
        if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0') return false;
        if (host.endsWith('.local') || host.endsWith('.internal')) return false;
        if (/^(10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|169\.254\.)/.test(host)) return false;
        return true;
    } catch {
        return false;
    }
}

// Validate CVE ID format
function isValidCVEId(id) {
    return /^CVE-\d{4}-\d{4,}$/i.test(id);
}

// Validate keyword search (alphanumeric + basic chars, max length)
function isValidSearchQuery(q) {
    if (!q || q.length > 200) return false;
    // Allow alphanumeric, spaces, hyphens, dots, underscores
    return /^[a-zA-Z0-9\s\-._]{1,200}$/.test(q);
}

// Middleware: validate param and reject bad input
function validateParam(paramName, validator, errorMsg) {
    return (req, res, next) => {
        const value = req.params[paramName];
        if (!value || !validator(value)) {
            auditLog(req, 'BLOCKED', `Invalid ${paramName}: ${(value || '').substring(0, 50)}`);
            return res.status(400).json({ error: errorMsg });
        }
        next();
    };
}

// ============================================
// 4. STATIC FILES (with cache control)
// ============================================

app.use(express.static(path.join(__dirname), {
    dotfiles: 'deny',              // Block .env, .git, etc.
    index: ['index.html'],
    maxAge: IS_PROD ? '1h' : 0,
    setHeaders: (res, filePath) => {
        // Never cache HTML (ensures CSP updates propagate)
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        }
    }
}));

// ============================================
// 5. API ROUTES (with validation + rate limiting)
// ============================================

// --- Health check & API status ---
app.get('/api/status', (req, res) => {
    res.json({
        status: 'ok',
        apis: {
            VT: !!process.env.VT_API_KEY,
            AbuseIPDB: !!process.env.ABUSEIPDB_API_KEY,
            IPInfo: !!process.env.IPINFO_TOKEN,
            OTX: !!process.env.OTX_API_KEY
        },
        security: {
            helmet: true,
            rateLimiting: true,
            ssrfProtection: true,
            corsLocked: IS_PROD
        }
    });
});

// --- VirusTotal v3 Proxy (validated + rate-limited) ---
app.get('/api/vt/ip/:ip', apiLimiter, validateParam('ip', isValidPublicIP, 'Invalid or private IP address.'), async (req, res) => {
    auditLog(req, 'VT_IP_LOOKUP', req.params.ip);
    await vtProxy(res, `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(req.params.ip)}`);
});

app.get('/api/vt/domain/:domain', apiLimiter, validateParam('domain', isValidDomain, 'Invalid domain name.'), async (req, res) => {
    auditLog(req, 'VT_DOMAIN_LOOKUP', req.params.domain);
    await vtProxy(res, `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(req.params.domain)}`);
});

app.get('/api/vt/file/:hash', apiLimiter, validateParam('hash', isValidHash, 'Invalid file hash. Must be MD5, SHA1, or SHA256.'), async (req, res) => {
    auditLog(req, 'VT_HASH_LOOKUP', req.params.hash);
    await vtProxy(res, `https://www.virustotal.com/api/v3/files/${encodeURIComponent(req.params.hash)}`);
});

app.get('/api/vt/url/:urlId', apiLimiter, async (req, res) => {
    const urlId = req.params.urlId;
    // URL IDs are base64-encoded, validate format
    if (!urlId || !/^[A-Za-z0-9\-_]+$/.test(urlId) || urlId.length > 500) {
        auditLog(req, 'BLOCKED', `Invalid VT URL ID: ${(urlId || '').substring(0, 50)}`);
        return res.status(400).json({ error: 'Invalid URL identifier.' });
    }
    auditLog(req, 'VT_URL_LOOKUP', urlId.substring(0, 30));
    await vtProxy(res, `https://www.virustotal.com/api/v3/urls/${encodeURIComponent(urlId)}`);
});

async function vtProxy(res, url) {
    const key = process.env.VT_API_KEY;
    if (!key) return res.status(503).json({ error: 'VirusTotal API key not configured on server.' });

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000); // 15s timeout

        const response = await fetch(url, {
            headers: { 'x-apikey': key },
            signal: controller.signal
        });
        clearTimeout(timeout);

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        if (err.name === 'AbortError') {
            return res.status(504).json({ error: 'VirusTotal request timed out.' });
        }
        console.error('VT proxy error:', err.message);
        res.status(500).json({ error: 'Failed to reach VirusTotal API.' });
    }
}

// --- AbuseIPDB v2 Proxy ---
app.get('/api/abuseipdb/:ip', apiLimiter, validateParam('ip', isValidPublicIP, 'Invalid or private IP address.'), async (req, res) => {
    const key = process.env.ABUSEIPDB_API_KEY;
    if (!key) return res.status(503).json({ error: 'AbuseIPDB API key not configured on server.' });

    auditLog(req, 'ABUSEIPDB_LOOKUP', req.params.ip);

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);

        const response = await fetch(
            `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(req.params.ip)}&maxAgeInDays=90&verbose`,
            {
                headers: { 'Key': key, 'Accept': 'application/json' },
                signal: controller.signal
            }
        );
        clearTimeout(timeout);

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        if (err.name === 'AbortError') {
            return res.status(504).json({ error: 'AbuseIPDB request timed out.' });
        }
        console.error('AbuseIPDB proxy error:', err.message);
        res.status(500).json({ error: 'Failed to reach AbuseIPDB API.' });
    }
});

// --- ipinfo.io Proxy ---
app.get('/api/ipinfo/:ip', apiLimiter, validateParam('ip', isValidPublicIP, 'Invalid or private IP address.'), async (req, res) => {
    const token = process.env.IPINFO_TOKEN;
    let url = `https://ipinfo.io/${encodeURIComponent(req.params.ip)}/json`;
    if (token) url += `?token=${token}`;

    auditLog(req, 'IPINFO_LOOKUP', req.params.ip);

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);

        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeout);

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        if (err.name === 'AbortError') {
            return res.status(504).json({ error: 'ipinfo request timed out.' });
        }
        console.error('ipinfo proxy error:', err.message);
        res.status(500).json({ error: 'Failed to reach ipinfo.io API.' });
    }
});

// --- URLhaus Proxy ---
app.post('/api/urlhaus', apiLimiter, async (req, res) => {
    const url = req.body.url;
    if (!url || typeof url !== 'string' || url.length > 2048) {
        auditLog(req, 'BLOCKED', 'Invalid URLhaus input');
        return res.status(400).json({ error: 'Invalid URL. Max 2048 characters.' });
    }

    auditLog(req, 'URLHAUS_LOOKUP', url.substring(0, 80));

    try {
        const formData = new URLSearchParams();
        formData.append('url', url);

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);

        const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
            method: 'POST',
            body: formData,
            signal: controller.signal
        });
        clearTimeout(timeout);

        const data = await response.json();
        res.json(data);
    } catch (err) {
        if (err.name === 'AbortError') {
            return res.status(504).json({ error: 'URLhaus request timed out.' });
        }
        console.error('URLhaus proxy error:', err.message);
        res.status(500).json({ error: 'Failed to reach URLhaus API.' });
    }
});

// --- NIST NVD Proxy ---
app.get('/api/nvd/cve', apiLimiter, async (req, res) => {
    const { cveId, keywordSearch } = req.query;

    let url;
    if (cveId) {
        if (!isValidCVEId(cveId)) {
            auditLog(req, 'BLOCKED', `Invalid CVE ID: ${(cveId || '').substring(0, 30)}`);
            return res.status(400).json({ error: 'Invalid CVE ID format. Expected CVE-YYYY-NNNNN.' });
        }
        url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
        auditLog(req, 'NVD_CVE_LOOKUP', cveId);
    } else if (keywordSearch) {
        if (!isValidSearchQuery(keywordSearch)) {
            auditLog(req, 'BLOCKED', `Invalid NVD search: ${(keywordSearch || '').substring(0, 50)}`);
            return res.status(400).json({ error: 'Invalid search query. Alphanumeric characters only, max 200 chars.' });
        }
        url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keywordSearch)}&resultsPerPage=15`;
        auditLog(req, 'NVD_KEYWORD_SEARCH', keywordSearch);
    } else {
        return res.status(400).json({ error: 'Provide cveId or keywordSearch query param.' });
    }

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 20000);

        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeout);

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        if (err.name === 'AbortError') {
            return res.status(504).json({ error: 'NVD request timed out.' });
        }
        console.error('NVD proxy error:', err.message);
        res.status(500).json({ error: 'Failed to reach NIST NVD API.' });
    }
});

// --- AlienVault OTX Proxy ---
app.get('/api/otx/pulses/subscribed', apiLimiter, async (req, res) => {
    auditLog(req, 'OTX_SUBSCRIBED_FETCH');
    await otxProxy(res, 'https://otx.alienvault.com/api/v1/pulses/subscribed?page=1&limit=20');
});

app.get('/api/otx/search', apiLimiter, async (req, res) => {
    const q = req.query.q || '';
    if (q.length > 200) {
        auditLog(req, 'BLOCKED', 'OTX search query too long');
        return res.status(400).json({ error: 'Search query too long. Max 200 characters.' });
    }
    auditLog(req, 'OTX_SEARCH', q.substring(0, 80));
    await otxProxy(res, `https://otx.alienvault.com/api/v1/search/pulses?q=${encodeURIComponent(q)}&page=1&limit=20`);
});

async function otxProxy(res, url) {
    const key = process.env.OTX_API_KEY;
    if (!key) return res.status(503).json({ error: 'AlienVault OTX API key not configured on server.' });

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);

        const response = await fetch(url, {
            headers: { 'X-OTX-API-KEY': key },
            signal: controller.signal
        });
        clearTimeout(timeout);

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        if (err.name === 'AbortError') {
            return res.status(504).json({ error: 'OTX request timed out.' });
        }
        console.error('OTX proxy error:', err.message);
        res.status(500).json({ error: 'Failed to reach AlienVault OTX API.' });
    }
}

// ============================================
// 6. ERROR HANDLING (no stack traces in prod)
// ============================================

// Block unknown routes — don't serve .env, .git, etc.
app.use((req, res) => {
    res.status(404).json({ error: 'Not found.' });
});

// Global error handler — never leak stack traces
app.use((err, req, res, _next) => {
    auditLog(req, 'SERVER_ERROR', err.message);
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: IS_PROD ? 'Internal server error.' : err.message
    });
});

// ============================================
// 7. START SERVER
// ============================================

app.listen(PORT, () => {
    console.log(`\n🛡️  CyberShield SOC Server running at http://localhost:${PORT}`);
    console.log(`   Mode: ${IS_PROD ? 'PRODUCTION' : 'DEVELOPMENT'}`);
    console.log(`\n   Security Controls:`);
    console.log(`   ✅ Helmet (CSP, HSTS, X-Frame-Options, etc.)`);
    console.log(`   ✅ Rate limiting (100/min global, 20/min API)`);
    console.log(`   ✅ SSRF protection (private IP blocking)`);
    console.log(`   ✅ Input validation on all proxy routes`);
    console.log(`   ✅ Request size limits (10 KB)`);
    console.log(`   ✅ Audit logging`);
    console.log(`   ✅ CORS ${IS_PROD ? 'restricted' : '(dev mode — permissive)'}`);
    console.log(`\n   API Key Status:`);
    console.log(`   VirusTotal:    ${process.env.VT_API_KEY ? '✅ Configured' : '❌ Not set'}`);
    console.log(`   AbuseIPDB:     ${process.env.ABUSEIPDB_API_KEY ? '✅ Configured' : '❌ Not set'}`);
    console.log(`   ipinfo.io:     ${process.env.IPINFO_TOKEN ? '✅ Configured' : '❌ Not set'}`);
    console.log(`   AlienVault OTX:${process.env.OTX_API_KEY ? '✅ Configured' : '❌ Not set'}`);
    console.log(`\n   Copy .env.example to .env and add your keys.\n`);
});
