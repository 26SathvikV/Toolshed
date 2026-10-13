/**
 * Toolshed is a web app for running Windows EXE files on Linux servers via Wine64, and converting documents to PDF via LibreOffice.
 * 
 * This is the main server file (index.js) that sets up the Express app, connects to MongoDB, defines models, handles authentication, and serves pages and APIs.
 * 
 * Environment variables:
 * - PORT: The port number for the server to listen on (default: 5000).
 * - MONGODB_URI: The MongoDB connection string.
 * - SESSION_SECRET: Secret for session cookies.
 * - SSO_SECRET: Secret for verifying SSO tokens.
 * - VIRUSTOTAL_API_KEY: API key for VirusTotal lookups.
 * - AUTH_HOST: URL of the central authentication host (optional).
 * - SITE_URL: Public URL of this site (optional).
 * 
 * Dependencies:
 * - express, express-session, connect-mongo, bcrypt, mongoose, path, express-rate-limit, child_process, crypto, fs, os
 */

// ── Imports ──────────────────────────────────────────────────────────────────
require('dotenv').config();
const express   = require('express');
const session   = require('express-session');
const { MongoStore } = require('connect-mongo');
const bcrypt    = require('bcrypt');
const mongoose  = require('mongoose');
const path      = require('path');
const rateLimit = require('express-rate-limit');
const { spawn } = require('child_process');
const crypto    = require('crypto');
const fs        = require('fs');
const os        = require('os');

// TLS compatibility for Node 18 + MongoDB Atlas
require('tls').DEFAULT_MAX_VERSION = 'TLSv1.2';

const app  = express();
const PORT = process.env.PORT || 5000;

app.disable('x-powered-by');

const MONGO_TLS_OPTS = { tls: true, tlsInsecure: true };

mongoose.connect(process.env.MONGODB_URI, MONGO_TLS_OPTS)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB error:', err));

// ── Models ────────────────────────────────────────────────────────────────────

const User = mongoose.model('User', new mongoose.Schema({
    name:                 String,
    email:                String,
    password:             String,   // bcrypt-hashed; field name matches Serenity's schema exactly
    plan:                 { type: String, enum: ['free','pro','studio'], default: 'free' },
    stripeCustomerId:     String,
    stripeSubscriptionId: String,
}));

const Run = mongoose.model('Run', new mongoose.Schema({
    userId:       mongoose.Schema.Types.ObjectId,
    fileName:     String,
    fileSize:     Number,
    architecture: String,
    subsystem:    String,
    isDLL:        Boolean,
    sections:     [String],
    imports:      [String],
    runAt:        { type: Date, default: Date.now }
}));

// Shared website registry
const Website = mongoose.model('Website', new mongoose.Schema({
    site_name:         String,
    link:              String,
    icon:              String,
    color:             String,
    order:             { type: Number, default: 0 },
    visible:           { type: Boolean, default: true },
    self:              { type: Boolean, default: false },
    hide_monetization: { type: Boolean, default: false },
    beta_test:         { type: Boolean, default: false }
}), 'websites');

// Tracks server-side daily usage (VT lookups) per user
const DailyUsage = mongoose.model('DailyUsage', new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, index: true },
    date:   { type: String, index: true },   // "YYYY-MM-DD" UTC
    vt:     { type: Number, default: 0 },
}), 'daily_usage');

const AUTH_HOST   = process.env.AUTH_HOST  || '';
const SITE_URL    = process.env.SITE_URL   || `http://localhost:${PORT}`;
const BILLING_URL = AUTH_HOST ? `${AUTH_HOST}/billing` : '';
const PLAN_TIER   = { free: 0, pro: 1, studio: 2 };
function isPlanAtLeast(user, minPlan) {
    return (PLAN_TIER[user?.plan] || 0) >= (PLAN_TIER[minPlan] || 0);
}

// Per-plan server-side limits (null = unlimited)
const PLAN_LIMITS = {
    free:   { vt: 3,    historyMax: 20   },
    pro:    { vt: null, historyMax: null },
    studio: { vt: null, historyMax: null },
};
function planLimits(user) { return PLAN_LIMITS[user?.plan] || PLAN_LIMITS.free; }

// ── SSO token verification ────────────────────────────────────────────────────
// Token format: base64url(JSON payload) + '.' + base64url(HMAC-SHA256 of the payload part)
function verifySsoToken(token) {
    const dot = token.indexOf('.');
    if (dot < 1 || dot === token.length - 1) return null;

    const payloadPart = token.slice(0, dot);
    const sigPart     = token.slice(dot + 1);

    const secret = process.env.SSO_SECRET;
    if (!secret) return null;

    const expected = crypto.createHmac('sha256', secret).update(payloadPart).digest('base64url');

    // Constant-time comparison to prevent timing attacks
    const eBuf = Buffer.from(expected, 'utf8');
    const aBuf = Buffer.from(sigPart,  'utf8');

    if (eBuf.length !== aBuf.length || !crypto.timingSafeEqual(eBuf, aBuf)) return null;
    try {
        const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));
        if (payload.exp && Date.now() > payload.exp) return null;   // expired
        return payload;
    } catch { return null; }
}

// Homepage can flip a suite-wide switch to hide monetization/upsell UI everywhere.
// Usage limits (PLAN_LIMITS) always keep enforcing regardless of this flag.
async function isMonetizationHidden() {
    const homepageDoc = await Website.findOne({ self: true }).select('hide_monetization').lean();
    return !!(homepageDoc && homepageDoc.hide_monetization);
}

// ── Rate limiters ─────────────────────────────────────────────────────────────

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 10,
    message: 'Too many attempts, please wait 15 minutes.',
    standardHeaders: true, legacyHeaders: false
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 100,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true, legacyHeaders: false
});

const wineLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 5,
    message: { error: 'Too many Wine64 requests, please wait 15 minutes.' },
    standardHeaders: true, legacyHeaders: false
});

const docsLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 20,
    message: { error: 'Too many document conversion requests, please wait 15 minutes.' },
    standardHeaders: true, legacyHeaders: false
});

// Detect available Wine64 execution method at startup
let wineMethod = null;
(function detectWine() {
    try { // Docker method
        const p = spawn('docker', ['info'], { stdio: 'ignore' });
        p.on('close', c => { if (c === 0 && !wineMethod) { wineMethod = 'docker'; console.log('Wine64: Docker available'); } });
        p.on('error', () => {});
    } catch {}
    try { // Direct wine64 method
        const p = spawn('wine64', ['--version'], { stdio: 'ignore' });
        p.on('close', c => { if (c === 0 && !wineMethod) { wineMethod = 'direct'; console.log('Wine64: direct wine64 available'); } });
        p.on('error', () => {});
    } catch {}
})();

// Detect LibreOffice for server-side document → PDF conversion
let docsMethod = null;
(function detectDocs() {
    try { // Docker method
        const p = spawn('docker', ['image', 'inspect', 'toolshed-docs'], { stdio: 'ignore' });
        p.on('close', c => { if (c === 0 && !docsMethod) { docsMethod = 'docker'; console.log('Docs: Docker available (toolshed-docs)'); } });
        p.on('error', () => {});
    } catch {}
    try { // Direct LibreOffice method
        const p = spawn('libreoffice', ['--version'], { stdio: 'ignore' });
        p.on('close', c => { if (c === 0 && !docsMethod) { docsMethod = 'direct'; console.log('Docs: LibreOffice direct available'); } });
        p.on('error', () => {});
    } catch {}
})();

// ── Middleware ────────────────────────────────────────────────────────────────

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
    secret:            process.env.SESSION_SECRET || 'toolshed-dev-secret',
    resave:            false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl:            process.env.MONGODB_URI,
        mongoClientOptions:  MONGO_TLS_OPTS,
        collectionName:      'sessions',
        ttl:                 7 * 24 * 60 * 60
    }),
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

// Cache siteInfo for 60 seconds so every page render doesn't hit MongoDB
let _siteInfoCache = null, _siteInfoAt = 0;

// Get site info (icon, color, link) from the shared websites collection
async function getSiteInfo() {
    if (_siteInfoCache && Date.now() - _siteInfoAt < 60_000) return _siteInfoCache;
    try {
        const site = await Website.findOne({ site_name: 'Toolshed' }).lean();
        _siteInfoCache = {
            siteIcon:  site?.icon  || 'code-slash-outline',
            siteColor: site?.color || '#000000',
            siteLink:  site?.link  || ''
        };
    } catch {
        _siteInfoCache = { siteIcon: 'code-slash-outline', siteColor: '#000000', siteLink: '' };
    }
    _siteInfoAt = Date.now();
    return _siteInfoCache;
}

// Render a page with the standard layout, injecting site info and monetization state
async function renderPage(res, pageName, locals = {}) {
    try {
        const siteInfo = await getSiteInfo();
        const monetizationHidden = await isMonetizationHidden();
        const pageLocals = { ...locals, billingUrl: BILLING_URL, monetizationHidden };
        const body = await new Promise((resolve, reject) => {
            res.app.render(`pages/${pageName}`, pageLocals, (err, html) => {
                if (err) reject(err); else resolve(html);
            });
        });
        res.render('standard/page', { ...pageLocals, ...siteInfo, body });
    } catch (e) {
        console.error('renderPage error:', e.message);
        res.status(500).send('An error occurred rendering this page.');
    }
}

// Get the currently logged-in user from the session, or null if not logged in
async function getUser(req) {
    if (!req.session.userId) return null;
    try { return await User.findById(req.session.userId); } catch { return null; }
}

// Check if a string is a valid MongoDB ObjectId
function isValidId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}

// ── Auth routes ───────────────────────────────────────────────────────────────
// Production: AUTH_HOST is set, so all auth is handled by the central home app.
// Dev:        AUTH_HOST is unset, so the local login/signup is served instead.

// Redirect to the central auth app's login/signup page with a redirect back to this site
function ssoLoginUrl(page = 'login') {
    const redirect = encodeURIComponent(`${SITE_URL}/auth/sso`);
    return `${AUTH_HOST}/${page}?redirect=${redirect}&app=toolshed`;
}

// Login page: redirects to SSO if AUTH_HOST is set, otherwise shows local login form
app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    if (AUTH_HOST) return res.redirect(ssoLoginUrl('login'));
    res.render('signup/login', { error: null });
});

// Local login, only reachable in dev (AUTH_HOST unset)
app.post('/login', authLimiter, async (req, res) => {
    const email    = String(req.body.email    || '').slice(0, 254).trim();
    const password = String(req.body.password || '').slice(0, 72);
    if (!email || !password)
        return res.render('signup/login', { error: 'Email and password are required.' });
    try {
        const user = await User.findOne({ email });
        if (!user)
            return res.render('signup/login', { error: 'No account found with that email.' });
        const ok = await bcrypt.compare(password, user.password);
        if (!ok)
            return res.render('signup/login', { error: 'Incorrect password.' });
        req.session.userId = user._id;
        res.redirect('/');
    } catch {
        res.render('signup/login', { error: 'Something went wrong. Please try again.' });
    }
});

// Signup page: redirects to SSO if AUTH_HOST is set, otherwise shows local signup form
app.get('/signup', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    if (AUTH_HOST) return res.redirect(ssoLoginUrl('signup'));
    res.render('signup/signup', { error: null });
});

// Local signup, only reachable in dev (AUTH_HOST unset)
app.post('/signup', authLimiter, async (req, res) => {
    const name     = String(req.body.name     || '').slice(0, 100).trim();
    const email    = String(req.body.email    || '').slice(0, 254).trim();
    const pass     = String(req.body.pass     || '').slice(0, 72);
    const passconf = String(req.body.passconf || '').slice(0, 72);
    if (!name || !email || !pass)
        return res.render('signup/signup', { error: 'All fields are required.' });
    if (pass !== passconf)
        return res.render('signup/signup', { error: 'Passwords do not match.' });
    if (pass.length < 8)
        return res.render('signup/signup', { error: 'Password must be at least 8 characters.' });
    try {
        const existing = await User.findOne({ email });
        if (existing)
            return res.render('signup/signup', { error: 'An account with that email already exists.' });
        const hashed = await bcrypt.hash(pass, 10);
        await new User({ name, email, password: hashed }).save();
        const user = await User.findOne({ email });
        req.session.userId = user._id;
        res.redirect('/');
    } catch {
        res.render('signup/signup', { error: 'Something went wrong. Please try again.' });
    }
});

// SSO callback, called by the central auth app after a successful login
app.get('/auth/sso', async (req, res) => {
    const token = String(req.query.token || '');
    if (!token) return res.redirect('/login');
    const payload = verifySsoToken(token);
    if (!payload || !payload.userId || !isValidId(String(payload.userId)))
        return res.redirect('/login?sso=fail');
    try {
        const user = await User.findById(payload.userId);
        if (!user) return res.redirect('/login?sso=fail');
        req.session.userId = user._id;
        res.redirect('/');
    } catch {
        res.redirect('/login?sso=fail');
    }
});

// Logout route: destroys the session and redirects to the central auth app's logout page if AUTH_HOST is set
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        if (AUTH_HOST) return res.redirect(`${AUTH_HOST}/logout?redirect=${encodeURIComponent(SITE_URL)}`);
        res.redirect('/login');
    });
});

// ── Page routes ───────────────────────────────────────────────────────────────

// Home page: shows the Run EXE tool and recent history
app.get('/', async (req, res) => {
    const user = await getUser(req);
    const lim  = planLimits(user);
    const runs = user ? await Run.find({ userId: user._id }).sort({ runAt: -1 }).limit(lim.historyMax ?? 50) : [];
    await renderPage(res, 'index', { name: 'Run EXE', user, runs });
});

// Convert page: shows the document → PDF conversion tool
app.get('/convert', async (req, res) => {
    const user = await getUser(req);
    await renderPage(res, 'convert', { name: 'Convert', user });
});

// Extract page: shows the PE file extraction tool
app.get('/extract', async (req, res) => {
    const user = await getUser(req);
    await renderPage(res, 'extract', { name: 'Extract', user });
});

// Tools page: shows the list of available tools and links to other ecosystem apps
app.get('/tools', async (req, res) => {
    const user = await getUser(req);
    await renderPage(res, 'tools', { name: 'Tools', user });
});

// ── API routes ────────────────────────────────────────────────────────────────

// This site's own entry, used by the client for the dynamic favicon
app.get('/api/self', async (_req, res) => {
    try {
        const site = await Website.findOne({ site_name: 'Toolshed' }, 'icon color').lean();
        res.json({ icon: site?.icon || null, color: site?.color || '#000000' });
    } catch { res.json({ icon: null, color: '#000000' }); }
});

// App switcher for the shared websites collection
app.get('/api/websites', apiLimiter, async (req, res) => {
    if (!req.session.userId) return res.status(401).json([]);
    try {
        const sites = await Website.find({ visible: { $ne: false } }, 'site_name link icon color order').sort({ order: 1 }).lean();
        res.json(sites);
    } catch { res.status(500).json([]); }
});

// VirusTotal hash lookup proxy
app.get('/api/vt/:hash', apiLimiter, async (req, res) => {
    // Enforce daily VT lookup limits per user plan
    if (!req.session.userId) return res.status(401).json({ error: 'Not logged in.' });
    const user  = await getUser(req);
    const lim   = planLimits(user);
    if (lim.vt !== null) {
        const today = new Date().toISOString().slice(0, 10);
        const usage = await DailyUsage.findOne({ userId: user._id, date: today }).lean();
        const used  = usage?.vt || 0;
        if (used >= lim.vt) {
            const monetizationHidden = await isMonetizationHidden();
            return res.status(429).json({
                dailyLimit: true, used, limit: lim.vt,
                error: `You've used all ${lim.vt} free VirusTotal lookups for today. Resets at midnight UTC.`,
                ...(monetizationHidden ? {} : { billingUrl: BILLING_URL })
            });
        }
        await DailyUsage.findOneAndUpdate(
            { userId: user._id, date: today },
            { $inc: { vt: 1 } },
            { upsert: true }
        );
    }

    // Validate the hash format (must be a 64-character hex string)
    const hash = req.params.hash;
    if (!/^[a-f0-9]{64}$/.test(hash))
        return res.status(400).json({ error: 'Invalid hash.' });

    // Query the VirusTotal API for the hash
    if (!process.env.VIRUSTOTAL_API_KEY)
        return res.json({ available: false });

    // Use the v3 API to get file report
    try {
        const r = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
            headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
        });
        if (r.status === 404) return res.json({ available: true, found: false });
        if (!r.ok)            return res.status(502).json({ error: 'VT API error.' });
        const d     = await r.json();
        const attrs = d?.data?.attributes || {};
        const stats = attrs.last_analysis_stats || {};
        res.json({
            available:  true, found: true,
            malicious:  stats.malicious  || 0,
            suspicious: stats.suspicious || 0,
            undetected: stats.undetected || 0,
            total:      (stats.malicious||0)+(stats.suspicious||0)+(stats.undetected||0)+(stats.harmless||0),
            name:       attrs.meaningful_name || '',
            link:       `https://www.virustotal.com/gui/file/${hash}`
        });
    } catch { res.status(502).json({ error: 'Could not reach VirusTotal.' }); }
});

// Save a run to history
app.post('/api/run', apiLimiter, async (req, res) => {
    // Validate user session and input
    if (!req.session.userId) return res.status(401).json({ error: 'Not logged in.' });
    const { fileName, fileSize, architecture, subsystem, isDLL, sections, imports } = req.body;

    // Validate input
    if (!fileName) return res.status(400).json({ error: 'Missing fileName.' });

    // Save the run to the database
    try {
        const run = new Run({
            userId:       req.session.userId,
            fileName:     String(fileName).slice(0, 260),
            fileSize:     Number(fileSize) || 0,
            architecture: String(architecture || '').slice(0, 50),
            subsystem:    String(subsystem    || '').slice(0, 50),
            isDLL:        Boolean(isDLL),
            sections: (Array.isArray(sections) ? sections : []).slice(0, 24).map(s => String(s).slice(0, 20)),
            imports:  (Array.isArray(imports)  ? imports  : []).slice(0, 64).map(s => String(s).slice(0, 80))
        });
        await run.save();
        // Rolling trim: keep only the N most recent runs for free-plan users
        const user = await getUser(req);
        const max  = planLimits(user).historyMax;
        if (max !== null) {
            const excess = await Run.find({ userId: req.session.userId })
                .sort({ runAt: -1 }).skip(max).select('_id').lean();
            if (excess.length) await Run.deleteMany({ _id: { $in: excess.map(r => r._id) } });
        }
        res.json({ ok: true, id: run._id });
    } catch { res.status(500).json({ error: 'Failed to save run.' }); }
});

// Delete a run from history
app.delete('/api/run/:id', apiLimiter, async (req, res) => {
    // Validate user session and input
    if (!req.session.userId) return res.status(401).json({ error: 'Not logged in.' });

    // Validate the run ID
    if (!isValidId(req.params.id)) return res.status(400).json({ error: 'Invalid ID.' });

    // Delete the run from the database
    try {
        await Run.deleteOne({ _id: req.params.id, userId: req.session.userId });
        res.json({ ok: true });
    } catch { res.status(500).json({ error: 'Failed to delete run.' }); }
});

// ── Wine64 server-side execution ──────────────────────────────────────────────

// Check if Wine64 is available on this server
app.get('/api/wine64/check', (req, res) => {
    res.json({ available: !!wineMethod, method: wineMethod || null });
});

// Run a Windows EXE file via Wine64 on the server, streaming stdout/stderr back to the client
app.post('/api/wine64/run',
    // Accept raw binary data (the EXE file) up to 200 MB
    express.raw({ type: 'application/octet-stream', limit: '200mb' }),
    wineLimiter,

    // Handle the request
    async (req, res) => {
        // Validate user session
        if (!req.session.userId) return res.status(401).json({ error: 'Not logged in.' });

        // Validate that Wine64 is available and that the request body contains file data
        if (!wineMethod) return res.status(503).json({ error: 'Wine64 is not available on this server. Requires Linux + wine64 or Docker.' });
        if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'No file data received.' });

        // Sanitize the file name from the query parameter, defaulting to "app.exe"
        const rawName = String(req.query.name || 'app.exe');
        const fileName = rawName.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100);
        if (!/\.exe$/i.test(fileName)) return res.status(400).json({ error: 'File must be an .exe' });

        // Create a temporary directory to store the uploaded EXE file
        let tmpDir;
        try { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wine64-')); }
        catch (e) { return res.status(500).json({ error: 'Could not create temp directory.' }); }

        // Write the uploaded EXE file to the temporary directory
        const exePath = path.join(tmpDir, fileName);
        try { fs.writeFileSync(exePath, req.body); }
        catch (e) { fs.rmSync(tmpDir, { recursive: true, force: true }); return res.status(500).json({ error: 'Could not write file.' }); }

        // Set up the response headers for Server-Sent Events (SSE) to stream logs back to the client
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Accel-Buffering', 'no');
        res.flushHeaders();

        // Helper function to send SSE messages to the client
        const send = (type, data = {}) => {
            if (!res.writableEnded) res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);
        };

        // Cleanup function to remove the temporary directory and clear the timeout
        const cleanup = () => {
            clearTimeout(timeout);
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        };

        // Log the start of the Wine64 execution
        send('log', { msg: `[Wine64] Starting ${fileName}...\n` });

        // Spawn the Wine64 process, either via Docker or directly, depending on the detected method
        let proc;
        try {
            if (wineMethod === 'docker') {
                proc = spawn('docker', [
                    'run', '--rm', '--network', 'none',
                    '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
                    '--security-opt', 'no-new-privileges:true',
                    '-v', `${exePath}:/app/${fileName}:ro`,
                    '-e', 'WINEDEBUG=-all',
                    'toolshed-wine64', 'wine64', `/app/${fileName}`
                ], { stdio: ['ignore', 'pipe', 'pipe'] });
            } else {
                proc = spawn('wine64', [exePath], {
                    env: { ...process.env, WINEDEBUG: '-all', HOME: tmpDir, WINEPREFIX: path.join(tmpDir, '.wine') },
                    stdio: ['ignore', 'pipe', 'pipe']
                });
            }
        } catch (e) {
            send('log', { msg: `[Wine64] Failed to start process: ${e.message}\n` });
            send('done', { code: -1 });
            res.end(); cleanup(); return;
        }

        // Set a timeout to kill the process if it runs longer than 60 seconds
        const timeout = setTimeout(() => {
            try { proc.kill('SIGTERM'); } catch {}
            send('log', { msg: '\n[Wine64] Timed out after 60 seconds.\n' });
            send('done', { code: -1, timedOut: true });
            res.end(); cleanup();
        }, 60000);

        // Stream stdout and stderr from the Wine64 process back to the client
        proc.stdout.on('data', d => send('log', { msg: d.toString() }));
        proc.stderr.on('data', d => send('log', { msg: d.toString() }));
        proc.on('close', code => {
            send('log', { msg: `\n[Wine64] Exited with code ${code}.\n` });
            send('done', { code });
            res.end(); cleanup();
        });
        proc.on('error', err => {
            send('log', { msg: `\n[Wine64] Error: ${err.message}\n` });
            send('done', { code: -1 });
            res.end(); cleanup();
        });

        // If the client disconnects, kill the Wine64 process and clean up
        req.on('close', () => { try { proc.kill('SIGTERM'); } catch {} cleanup(); });
    }
);

// ── Document → PDF conversion (LibreOffice) ───────────────────────────────────

// Check if document conversion is available on this server
app.get('/api/docs/check', (req, res) => {
    res.json({ available: !!docsMethod, method: docsMethod || null });
});

// Convert a document to PDF using LibreOffice, either via Docker or directly
app.post('/api/docs/convert',
    // Accept raw binary data (the document file) up to 50 MB
    express.raw({ type: 'application/octet-stream', limit: '50mb' }),
    docsLimiter,

    // Handle the request
    async (req, res) => {
        // Validate user session
        if (!req.session.userId) return res.status(401).json({ error: 'Not logged in.' });

        // Validate that document conversion is available and that the request body contains file data
        if (!docsMethod) return res.status(503).json({ error: 'Document conversion is not available on this server. Build the toolshed-docs Docker image (see README).' });
        if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'No file data received.' });

        // Sanitize the file name from the query parameter, defaulting to "document"
        const rawName = String(req.query.name || 'document');
        const fileName = rawName.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100);
        const outName  = fileName.replace(/\.[^.]+$/, '.pdf');

        // Create a temporary directory to store the uploaded document file
        let tmpDir;
        try { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'docs-')); }
        catch (e) { return res.status(500).json({ error: 'Could not create temp directory.' }); }

        // Write the uploaded document file to the temporary directory
        const inPath = path.join(tmpDir, fileName);
        try { fs.writeFileSync(inPath, req.body); }
        catch (e) { fs.rmSync(tmpDir, { recursive: true, force: true }); return res.status(500).json({ error: 'Could not write file.' }); }

        // Attempt to convert the document to PDF using LibreOffice
        try {
            // Run LibreOffice in headless mode to convert the document to PDF, either via Docker or directly
            await new Promise((resolve, reject) => {
                let proc;
                if (docsMethod === 'docker') {
                    proc = spawn('docker', [
                        'run', '--rm', '--network', 'none',
                        '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
                        '--security-opt', 'no-new-privileges:true',
                        '-v', `${tmpDir}:/work`,
                        'toolshed-docs',
                        'libreoffice', '--headless', '--convert-to', 'pdf', '--outdir', '/work', `/work/${fileName}`
                    ], { stdio: 'ignore' });
                } else {
                    proc = spawn('libreoffice', [
                        '--headless', '--convert-to', 'pdf', '--outdir', tmpDir, inPath
                    ], { stdio: 'ignore', env: { ...process.env, HOME: tmpDir } });
                }
                const timeout = setTimeout(() => {
                    try { proc.kill(); } catch {}
                    reject(new Error('Conversion timed out after 2 minutes.'));
                }, 120000);
                proc.on('close', code => {
                    clearTimeout(timeout);
                    if (code === 0) resolve();
                    else reject(new Error(`LibreOffice exited with code ${code}.`));
                });
                proc.on('error', err => { clearTimeout(timeout); reject(err); });
            });

            // Check if the output PDF was created successfully
            const outPath = path.join(tmpDir, outName);
            if (!fs.existsSync(outPath)) throw new Error('Output PDF was not created: the file format may be unsupported.');

            // Send the resulting PDF file back to the client as a download
            const pdf = fs.readFileSync(outPath);
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="${outName}"`);
            res.send(pdf);
        } catch (e) {
            if (!res.headersSent) res.status(500).json({ error: e.message || 'Conversion failed.' });
        } finally {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        }
    }
);

// ── 404 ───────────────────────────────────────────────────────────────────────

app.use(async (req, res) => {
    const siteInfo = await getSiteInfo();
    res.status(404).render('standard/page', {
        name: '404', user: null, ...siteInfo,
        body: '<div style="text-align:center;padding:80px 0"><h1>404</h1><p>Page not found.</p><a href="/">Go Home</a></div>'
    });
});

// Start the server
app.listen(PORT, () => console.log(`Toolshed running on http://localhost:${PORT}`));
