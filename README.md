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
- Runtime: Node 20+

Optional environment variables:

- `MONGODB_CONNECTIONSTRING` or `DATABASE_URL`
- `MONGODB_USERNAME`
- `MONGODB_PASSWORD`
- `MONGODB_CERT_PATH`
- `RESULTS_FILE`
- `PUPPETEER_CACHE_DIR` (Render default: `/opt/render/project/src/.cache/puppeteer`)

The included `render.yaml` sets production mode and Puppeteer's cache directory for Render. Chrome is installed during `npm ci` through the `postinstall` script.
