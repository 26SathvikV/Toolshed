# Toolshed

Toolshed is a multi-purpose Windows-focused toolkit for PE inspection, archive extraction, file conversion, and browser-side utility tools. Drop any `.exe`, `.dll`, or `.sys` file and get a PE breakdown, heuristic threat analysis, and a simulation of how Windows would load it. 32-bit apps can run client-side via Boxedwine (WebAssembly); 64-bit apps run server-side via Wine64 when Docker is available.

---

## For everyone: what does this app do?

### Run EXE (home page)

Drop any Windows `.exe`, `.dll`, or `.sys` file onto the page. The app immediately shows you:

| Item | Meaning |
|---|---|
| **File type** | Whether it's an executable (.exe) or a shared library (.dll) |
| **Architecture** | Whether it was built for 32-bit or 64-bit Windows, or ARM |
| **Subsystem** | Whether it's a command-line (console) or graphical (GUI) app |
| **Compile timestamp** | When the developer built it (or "Not set" if it was stripped) |
| **Sections** | Internal layout of the file (code, data, resources…) |
| **Imports** | Which Windows system DLLs the program depends on |

**Security scan**: right below the file info, the scanner looks for suspicious patterns, as shown below.
- **High risk**: packed/obfuscated code, process injection APIs, keylogger calls
- **Suspicious**: encrypted sections, registry persistence, process spawning
- **Low risk**: minor anomalies (stripped timestamp, very few imports)
- **Clean**: no suspicious patterns found
- **SHA-256 hash** is computed in the browser and displayed. Click it to copy, then click **VirusTotal** to check if any antivirus engine has seen this file before.

**Threat warnings**: if suspicious imports are detected, toast notifications appear in the top-right with context-aware explanations (e.g. registry read + write together → settings storage, not persistence). Warnings auto-fade and can be downloaded as a log.

**Simulate**: click **▶ Simulate** for a terminal-style walkthrough of what would happen if Windows loaded the file: import resolution, entry point, console output or GUI window lifecycle. No code is executed because this is metadata-driven.

**Run in Emulator**: click to run the EXE:

- 32-bit apps run via [Boxedwine](https://github.com/danoon2/Boxedwine) (Wine compiled to WebAssembly) entirely in the browser. Nothing leaves your machine.
- 64-bit apps are uploaded to the server and run via Wine64 inside Docker (or native `wine64` on Linux). Output streams back in real time. Requires server-side setup (see below).

**Run App from Folder / ZIP**: For multi-file apps (games, installers) that ship as a folder, zip the entire folder and drop it in the "Run App from ZIP" section. The emulator receives all the files.

> UNDERTALE and DELTARUNE, for example, need their full folder (EXE + `data.win` + audio files). Zip the folder, drop it, select the EXE, and click Run in Emulator. Save files won't persist between sessions.

### Tools (second page)

In-browser encoding, text, and number utilities:

| Tool | Purpose |
|---|---|
| Base64 | encode/decode text or any file |
| URL encoding | encode and decode URIs |
| HTML entities | encode and decode HTML special characters |
| Text transformer | uppercase, lowercase, title case, camelCase, snake_case, kebab-case, reverse, sort lines, deduplicate, trim whitespace; word/character/line/sentence counter |
| Number base converter | decimal ↔ hex ↔ binary ↔ octal |
| Hash generator | MD5, SHA-1, SHA-256, SHA-512 (text or file) |
| Unix timestamp | convert between Unix seconds and human-readable datetime |
| Markdown preview | live render with syntax highlighting |
| Color tools | pick a color and convert between hex, RGB, HSL, HSV, CMYK; contrast ratio checker |

### Extract (third page)

Browse the contents of archive files without extracting them to disk. Drop a file and immediately see the full file tree, sizes, and type icons. Download individual entries or repack everything as a new ZIP.

Supported formats: ZIP · TAR · TAR.GZ · TAR.BZ2 · TAR.XZ · TAR.ZST · 7Z · RAR (v4) · CAB · AR / .a / .deb · ISO · LHA/LZH · CPIO · XAR · RPM · WARC · and more via libarchive.

Not supported: `.lrzip`, `.ace`, `.arj`, `.zoo`, RAR5 with encryption, and other proprietary algorithms not in libarchive.

### Convert (fourth page)

In-browser file and media conversions:

- **Documents**: DOCX / ODT / RTF / PPTX / XLSX and other office formats to PDF when LibreOffice is available
- **Images**: PNG, JPEG, WebP, and more; quality settings when supported
- **Data**: CSV, JSON, YAML, XML, TSV, and other structured format conversions
- **Text**: document and content conversion paths for browser-side output
- **Bulk queue**: add several files, pick output formats, and download the results as a ZIP

---

## For developers

### Stack

| Layer | Technology |
|---|---|
| Server | Node.js 18 + Express 4 |
| Templating | EJS (same pattern as Serenity & Catalogue) |
| Database | MongoDB Atlas via Mongoose |
| Auth | express-session + connect-mongo + bcrypt (dev); SSO via HMAC-SHA256 token (production) |
| Security | express-rate-limit; `X-Powered-By` header removed; `httpOnly` + `sameSite: lax` cookies; ObjectId validation; input sanitization on all user-controlled fields |
| Client | Vanilla JS (no framework); SubtleCrypto API for SHA-256/hashing; fflate (CDN) for ZIP; libarchive.js (CDN WASM) for archives; Boxedwine (self-hosted WASM) for 32-bit EXE emulation |
| Wine64 | Docker (`toolshed-wine64` image from `Dockerfile.wine`) or native `wine64` on Linux |
| Icons | Ionicons 7 (web components via CDN) |

### Project structure

```
Toolshed/
├── index.js                  Express app: models, routes, middleware
├── Dockerfile.wine           Builds the toolshed-wine64 Docker image (Ubuntu + wine64)
├── .env                      Secrets (gitignored, never committed)
├── .env.example              Template showing required variables
├── views/
│   ├── standard/page.ejs     Shared layout: header, nav, site switcher, cookie banner
│   ├── pages/
│   │   ├── index.ejs         Home, PE parser, threat scanner, simulation, emulator, and history
│   │   ├── tools.ejs         Encoding, text, number, and color utilities
│   │   ├── extract.ejs       Archive extraction (libarchive WASM via CDN)
│   │   └── convert.ejs       File converter (image, CSV/JSON)
│   └── signup/
│       ├── login.ejs         Login page
│       └── signup.ejs        Sign-up page
├── public/
│   ├── style.css             CSS custom properties for all 17 color schemes
│   └── boxedwine/            (not in repo; download separately, see below)
│       ├── boxedwine.js
│       └── boxedwine.wasm
└── .github/workflows/
    └── release.yml           CI: builds standalone binaries for Win/Mac/Linux via pkg
```

### Shared ecosystem wiring

| Thing | Detail |
|---|---|
| Database | `test` db on the shared Atlas cluster |
| `users` collection | `{ name, email, password, plan, stripeCustomerId, stripeSubscriptionId, storageUsed }`, `plan` is `'free' \| 'pro' \| 'studio'`; billing managed by the home page; `storageUsed` incremented by Catalogue on uploads |
| `runHistory` collection | PE scan results and metadata per user; trimmed to 20 entries on free plan |
| `dailyUsages` collection | Server-side VirusTotal call count per user per UTC date |
| `sessions` collection | connect-mongo; TTL 7 days; same `SESSION_SECRET` = SSO across all apps |
| `websites` collection | `{ site_name, link, icon, color }`, shared registry for the app switcher |
| `CatalogueNotification` collection | Toolshed can write here to send cross-app inbox notifications to users in Catalogue |
| `colorScheme` cookie | Synced across apps with user consent; read from cookie first, localStorage fallback |
| Port | 5000 (Serenity: 3000, Catalogue: 4000) |

### Security hardening

- **Rate limiting**: auth routes capped at 10 requests / 15 min; all API routes capped at 100 / 15 min (`express-rate-limit`); Wine64 route has its own stricter limiter
- **Input sanitization**: all user-supplied strings are sliced to safe lengths before any DB operation
- **ObjectId validation**: `mongoose.Types.ObjectId.isValid()` checked before every delete
- **No stack traces exposed**: production errors return a generic message; details go to `console.error` only
- **Client-side analysis**: PE parser, entropy analysis, SHA-256, and all tool operations run in the browser; only metadata (name, size, arch) is sent to the server for history saves
- **Wine64 uploads**: when running a 64-bit EXE server-side, the file is uploaded over HTTPS, written to a temp directory with a sanitized filename, run in an isolated Docker container (`--network none`, memory-limited), then the temp directory is deleted immediately
- **VirusTotal proxy**: the API key stays on the server; the client sends only a SHA-256 hash, never the file
- **`X-Powered-By` disabled**: `app.disable('x-powered-by')` prevents fingerprinting
- **Secure session cookies**: `httpOnly: true`, `sameSite: 'lax'`

### Environment variables

Copy `.env.example` to `.env` and fill in your values:

```
PORT=5000
MONGODB_URI=mongodb+srv://<user>:<pass>@<cluster>.mongodb.net/test
SESSION_SECRET=<same value as Serenity and Catalogue>

# SSO (production only, leave blank in dev to use local auth)
AUTH_HOST=            # URL of the central home/auth app
SITE_URL=             # Public URL of this app (for SSO redirect-back)
SSO_SECRET=           # Shared HMAC secret matching home app's SSO_SECRET

VIRUSTOTAL_API_KEY=   # optional, free at virustotal.com
```

In dev (no `AUTH_HOST`), `/login` and `/signup` use local bcrypt auth. In production, they redirect to `AUTH_HOST/login` and authenticate via a signed SSO token on return.

### Boxedwine emulator setup (32-bit)

The "Run in Emulator" feature uses [Boxedwine](https://github.com/danoon2/Boxedwine) (by danoon2) to run 32-bit Windows EXEs in the browser. The web build files are not stored in the git repo and must be placed manually.
> (Note: Wine is compiled to WebAssembly via Emscripten) 

1. Go to [Boxedwine GitHub Releases](https://github.com/danoon2/Boxedwine/releases)
2. Download the latest **web** build zip
3. Extract the **entire** zip into `public/boxedwine/`, and you should end up with:
   ```
   public/boxedwine/
   ├── SingleThreaded/
   │   ├── boxedwine.js
   │   ├── boxedwine.wasm
   │   └── boxedwine.zip   (Wine 6 root filesystem)
   ├── MultiThreaded/
   │   └── ...
   ├── Wine11/
   │   └── boxedwine.zip   (Wine 11 root filesystem, optional upgrade)
   └── readme.txt
   ```
4. Restart the server, and the emulator button will activate automatically

The app uses the **SingleThreaded** build by default (no special HTTP headers required). The MultiThreaded build is faster but requires `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` headers.

**Limitations**: OpenGL and Direct3D are not supported in the WebAssembly build. Most 32-bit and 16-bit Windows apps, games with DirectDraw, and console applications will run.

### Document → PDF setup (LibreOffice)

DOCX, DOC, RTF, ODT, PPTX, PPT, ODP, XLSX, XLS, ODS → PDF conversion runs server-side via LibreOffice. Without this, those formats only offer text/HTML output.

**Docker setup:**

```bash
docker build -f Dockerfile.docs -t toolshed-docs .
```

This builds an Ubuntu 22.04 image with LibreOffice Writer, Calc, Impress, and Microsoft-compatible fonts. Build takes ~3 minutes (~900MB image); only needs to happen once per machine.

Restart the server after building, and you should see `Docs: Docker available (toolshed-docs)` in the console.

**Without LibreOffice**: all other conversions (images, audio/video, text, data formats) continue to work. Document types will only offer their client-side output options (HTML, plain text).

### Wine64 setup (64-bit)

64-bit EXEs are automatically detected and routed to the server for execution. The server checks for two methods at startup (in order):

1. **Docker**: `docker info` succeeds → runs `toolshed-wine64` image
2. **Native**: `wine64 --version` succeeds → runs `wine64` directly (Linux only)

**Docker setup (recommended for dev on Windows/Mac):**

```bash
docker build -f Dockerfile.wine -t toolshed-wine64 .
```

This builds an Ubuntu 22.04 image with `wine64` and pre-initializes the Wine prefix (`wineboot --init`). Build takes ~2 minutes; only needs to happen once per machine.

Restart the server after building, and you should see `Wine64: Docker available` in the console.

**Without Wine64**: the 64-bit branch shows an informational message; 32-bit emulation and all other features continue to work normally.

### Running locally

```bash
git clone <repo-url>
cd Toolshed
npm install
cp .env.example .env   # then edit .env with your credentials
npm start              # or: npm run dev  (nodemon watch mode)
```

Open `http://localhost:5000`.

### Building standalone binaries (CI)

The release workflow uses [`pkg`](https://github.com/vercel/pkg) to bundle the entire app (server, views, and public assets) into a single executable per platform. No Node.js installation required on the target machine.

**Manual build:**

```bash
npm install -g pkg
pkg . --target node18-win-x64   --output dist/Toolshed-Windows.exe
pkg . --target node18-macos-x64 --output dist/Toolshed-macOS
pkg . --target node18-linux-x64 --output dist/Toolshed-Linux
```

The binary reads `.env` from the directory it is run from. Ship the binary and tell users to create a `.env` file alongside it.

**Via GitHub Actions:**

Push a version tag:

```bash
git tag v1.0.0
git push --tags
```

The workflow builds all three platforms in parallel and uploads them to the GitHub Release automatically.

### API reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/self` | none | Returns this site's `icon` and `color` from the `websites` collection (used for the dynamic favicon) |
| `GET` | `/api/websites` | required | Returns all entries from the `websites` collection for the app switcher |
| `GET` | `/api/vt/:hash` | none | Proxies a VirusTotal SHA-256 lookup; returns `{ dailyLimit, used, limit }` on 429 when the daily cap is reached |
| `POST` | `/api/run` | required | Saves a run to history; trims to plan limit |
| `DELETE` | `/api/run/:id` | required | Deletes a run from history |
| `GET` | `/api/wine64/check` | none | Returns `{ available, method }` for whether Wine64 is set up on this server |
| `POST` | `/api/wine64/run?name=<file>` | required | Streams Wine64 execution output via SSE; request body is raw EXE bytes (`application/octet-stream`) |

### Client-side PE parser

All binary analysis runs in the browser using the [FileReader API](https://developer.mozilla.org/en-US/docs/Web/API/FileReader) and raw `DataView` operations on the `ArrayBuffer`. No binary is sent to the server.

**What is parsed:**

- MZ signature and PE signature at the offset given by `e_lfanew`
- COFF header: machine type, section count, timestamp, characteristics
- Optional header: PE magic (PE32 vs PE32+), subsystem
- Section table: names, virtual addresses, raw offsets, sizes
- Import directory (data directory index 1): DLL names **and function names** from the Import Lookup Table
- Shannon entropy per section (sampled up to 64 KB) for packing detection

**Virus heuristic scoring** (risk score 0–100):

| Pattern | Points |
|---|---|
| Known packer section name (UPX, Themida, …) | +40 |
| High-entropy section (> 7.2 bits/byte, > 4 KB) | +15 each, max +45 |
| No imports at all | +35 |
| < 2 imports for a large file | +20 |
| CreateRemoteThread / WriteProcessMemory | +30–35 |
| SetWindowsHookEx (keylogger indicator) | +25 |
| CryptEncrypt (ransomware indicator) | +20 |
| Timestamp is zero | +10 |

Thresholds:
0–20 | Clean
21–50 | Low risk
51–75 | Suspicious
76–100 | High risk

**Context-aware threat warnings**: suspicious imports trigger toast notifications with explanations that consider import *combinations*, not just individual flags (e.g. registry read + write together is likely settings storage; `IsDebuggerPresent` alone is common in release C/C++ builds; `ShellExecute` in a GUI app usually just opens a browser link).

---

## Credits

| Project | Author | Use |
|---|---|---|
| [Boxedwine](https://github.com/danoon2/Boxedwine) | danoon2 | In-browser 32-bit Windows emulator: Wine compiled to WebAssembly via Emscripten |
| [libarchive.js](https://github.com/nika-begiashvili/libarchive.js) | nika-begiashvili | WASM port of libarchive; powers the archive extraction page |
| [fflate](https://github.com/101arrowz/fflate) | 101arrowz | Pure-JS ZIP library; used for in-browser ZIP extraction |
| [Ionicons](https://ionic.io/ionicons) | Ionic | Icon set used throughout the UI |
