# PanelCheckers

Node.js + Express web service prepared for Render deployment.

## Local run

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Render deploy

Use this repository as a Render Web Service.

- Build command: `npm ci`
- Start command: `npm start`
- Health check path: `/health`
- Runtime: Node 22.12+

Optional environment variables:

- `MONGODB_CONNECTIONSTRING` or `DATABASE_URL`
- `MONGODB_USERNAME`
- `MONGODB_PASSWORD`
- `MONGODB_CERT_PATH`
- `SESSION_SECRET` (production için zorunlu, uzun ve rastgele bir değer kullanın)
- `ADMIN_USERNAME` (yalnızca boş `users` koleksiyonunda ilk admin bootstrap işlemi için)
- `ADMIN_PASSWORD` (ilk admin için en az 8 karakter)
- `RESULTS_FILE`
- `PUPPETEER_CACHE_DIR` (Render default: `/opt/render/project/src/.cache/puppeteer`)
- `BROWSER_HEADLESS` (Render default: `1`)
- `CHECK_ALLOWED_HOSTS` (production default: `atrtouristik.com`)
- `CHECK_ALLOWED_ROOT_DOMAINS` (production default: `atrtouristik.com`)
- `CHECK_ENFORCE_ALLOWED_ROOT_DOMAINS` (production default: `true`)

The included `render.yaml` sets production mode, Puppeteer's cache directory, headless browser mode, and production domain restrictions for Render. Chrome is installed during `npm ci` through the `postinstall` script.

## Authentication and permissions

Authentication is DB-only after the first bootstrap. If the MongoDB `users`
collection is empty, the service creates the first admin from `ADMIN_USERNAME`
and `ADMIN_PASSWORD`. Existing users are never overwritten from environment
variables on later starts.

An admin can create, update, disable, reset the password of, or delete users
from the `Kullanıcı ve Yetki Yönetimi` panel. Permissions are checked against
MongoDB on every authenticated request, so role, permission, and active-state
changes apply to existing sessions immediately.
