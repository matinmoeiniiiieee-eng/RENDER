# Deploying REN on Deplexo

## راهنمای سریع (فارسی)

1. در [deplexo.com](https://deplexo.com) وارد شوید، گیت‌هاب را وصل کنید و همین ریپو را انتخاب کنید (برنچ `NEW`).
2. نوع اپ را **Web** بگذارید. بقیه تنظیمات بیلد از `deplexo.yaml` خوانده می‌شود (Dockerfile، پورت 8000).
3. در بخش Environment Variables حتماً `ADMIN_PASSWORD` را با یک رمز قوی (حداقل ۸ کاراکتر) تنظیم کنید.
4. (اختیاری ولی توصیه‌شده) `PUBLIC_DOMAIN` را برابر آدرس اپ بگذارید، مثلاً `my-app.de.deplexo.com`. اگر نگذارید، کافی است یک‌بار `/login` را از آدرس عمومی باز کنید تا دامنه خودکار تشخیص داده و ذخیره شود.
5. مطمئن شوید Storage اپ روی مسیر `/data` (پیش‌فرض دپلکسو) مانت است تا لینک‌ها و رمز پنل بعد از ری‌دیپلوی پاک نشوند.
6. Deploy را بزنید، سپس `https://<your-app>/login` را باز کنید.

### عیب‌یابی: تلگرام وصل است ولی عکس/فیلم دانلود نمی‌شود، یوتیوب/گوگل باز نمی‌شود

این مشکلات در این نسخه برطرف شده‌اند:

- **IPv6 خراب در کانتینر**: گوگل/یوتیوب رکورد IPv6 دارند و سرور قبلاً اول به IPv6 وصل می‌شد که در کانتینر کار نمی‌کند و تا تایم‌اوت گیر می‌کرد. حالا IPv6 خودکار تست می‌شود (`REN_IPV6=auto`)، IPv4 اولویت دارد و اتصال‌ها به‌صورت Happy Eyeballs موازی امتحان می‌شوند.
- **UDP پشتیبانی نمی‌شد**: DNS ریموت (پورت 53) و QUIC (UDP 443 یوتیوب/گوگل) رد می‌شدند. حالا VLESS UDP پشتیبانی می‌شود (`REN_UDP=true`).
- **قطع شدن دانلودهای طولانی**: تایم‌اوت بیکاری قبلاً برای هر جهت جدا حساب می‌شد و دانلود بزرگ با آپلود ساکت بعد از ۵ دقیقه قطع می‌شد. حالا فقط وقتی هیچ ترافیکی در هیچ جهتی نباشد قطع می‌شود.
- **کندی DNS**: هر اتصال دو بار DNS می‌گرفت روی ۵ ترد. حالا کش DNS + ۳۲ ترد اختصاصی.
- **سقف سرعت**: بافر سوکت ثابت ۲۵۶KB جلوی autotuning لینوکس را می‌گرفت (مخصوصاً برای دیتاسنترهای دور تلگرام). حذف شد.

نکات سمت کلاینت (v2rayNG / Hiddify / NekoBox):

- **Mux را خاموش کنید** (Mux/XUDP پشتیبانی نمی‌شود).
- اگر بعد از آپدیت هنوز یوتیوب کند است، در خطاهای پنل دنبال `IPv6` یا `DNS lookup failed` بگردید.
- اگر گوگل کپچا یا «unusual traffic» نشان داد، IP دیتاسنتر Deplexo توسط گوگل محدود شده؛ این ربطی به کد ندارد.

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

**Network tuning** (all optional, defaults suit Deplexo): `REN_UDP`, `REN_IPV6` (`auto`/`on`/`off`), `REN_PREFER_IPV6`, `REN_IDLE_TIMEOUT`, `REN_UDP_IDLE_TIMEOUT`, `REN_CONNECT_TIMEOUT`, `REN_DNS_CACHE_TTL`, `REN_DNS_WORKERS`, `REN_WS_PING_INTERVAL`, `REN_SOCKET_BUFFER`, `REN_UVLOOP`. See `.env.example`.
