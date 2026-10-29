# Deploying REN on Deplexo

## راهنمای سریع (فارسی)

1. در [deplexo.com](https://deplexo.com) وارد شوید، گیت‌هاب را وصل کنید و همین ریپو را انتخاب کنید (برنچ `NEW`).
2. نوع اپ را **Web** بگذارید. بقیه تنظیمات بیلد از `deplexo.yaml` خوانده می‌شود (Dockerfile، پورت 8000).
3. در بخش Environment Variables حتماً `ADMIN_PASSWORD` را با یک رمز قوی (حداقل ۸ کاراکتر) تنظیم کنید.
4. (اختیاری ولی توصیه‌شده) `PUBLIC_DOMAIN` را برابر آدرس اپ بگذارید، مثلاً `my-app.de.deplexo.com`. اگر نگذارید، کافی است یک‌بار `/login` را از آدرس عمومی باز کنید تا دامنه خودکار تشخیص داده و ذخیره شود.
5. مطمئن شوید Storage اپ روی مسیر `/data` (پیش‌فرض دپلکسو) مانت است تا لینک‌ها و رمز پنل بعد از ری‌دیپلوی پاک نشوند.
6. Deploy را بزنید، سپس `https://<your-app>/login` را باز کنید.

## English

**What Deplexo needs and how this repo provides it**

| Deplexo requirement | Where it is handled |
| --- | --- |
| Dockerfile or auto-detect config | `Dockerfile` + `deplexo.yaml` (`framework: dockerfile`, `run.port: 8000`) |
| Listen on `0.0.0.0:$PORT` | `deplexo_main.py` binds `0.0.0.0:$PORT`; `run.port` sets `PORT=8000` |
| Read-only root filesystem | State goes to `DATA_DIR=/data` (persistent mount); falls back to `/tmp/ren` with a warning if `/data` is not writable; `PYTHONDONTWRITEBYTECODE=1` |
| Unprivileged user | Image runs as UID 10001; `/data` is owned by it |
| Graceful shutdown | Exec-form `CMD`, Hypercorn handles SIGTERM and flushes state |
| Health | Docker `HEALTHCHECK` on `/health` |
| No public-URL env var (unlike Render/Railway) | `PUBLIC_DOMAIN` env var, or auto-detected from the Host header of `/login`, `/dashboard`, `/sub/*` requests and persisted in `/data/deplexo_domain.txt` |

**Steps**

1. Sign in at deplexo.com, connect GitHub, pick this repository and branch.
2. App type: **Web**. Build settings come from `deplexo.yaml`.
3. Environment variables:
   - `ADMIN_PASSWORD` (required, 8+ chars)
   - `PUBLIC_DOMAIN` (recommended, e.g. `my-app.de.deplexo.com` or your custom domain)
   - `ALLOW_PRIVATE_RANGES=false` (default)
4. Storage: keep the data mount at `/data` (Deplexo default). If you change it, set `DATA_DIR` to match.
5. Deploy, then open `https://<your-app>/login`.

If you attach a custom domain later, set `PUBLIC_DOMAIN` to it (or set it from the panel's domain setting) and redeploy.

Render (`render.yaml`, `Procfile`) and Railway (`railway.json`) setups are unchanged and still start `main.py` directly.
