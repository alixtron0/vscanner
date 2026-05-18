# scanner.py — راهنمای فارسی

> **English:** [Read the English README here](README.md)

یک اسکنر شبکه برای آی‌پی‌های Vercel، دامنه‌های CDN و هاست‌های مورد استفاده در domain fronting. هر هدف را با چند پروتکل مختلف بررسی می‌کنه، تاخیر شبکه رو اندازه می‌گیره و نتایج رو از بهترین به بدترین مرتب ذخیره می‌کنه.

هیچ نیازی به `pip install` نداره. روی Ubuntu و CentOS مستقیم کار می‌کنه.

---

## چی‌کار می‌کنه

- رنج‌های IP مربوط به Vercel رو باز می‌کنه و تک‌تک اسکن می‌کنه
- دامنه‌های CDN و domain-fronting رو تست می‌کنه (Cloudflare، Akamai، CloudFront، Fastly، Azure، Google، Netlify و بقیه)
- چند پروتکل همزمان: TCP، HTTP، HTTPS، ICMP، DNS، TLS
- RAM و CPU سرور رو تشخیص می‌ده و تنظیمات بهینه پیشنهاد می‌ده
- اسکن رو در پس‌زمینه اجرا می‌کنه — می‌تونی ترمینال رو ببندی
- هر لحظه که خواستی وضعیت اسکن رو چک کنی
- نتایج مرتب‌شده بر اساس میانگین ping ذخیره می‌شه

---

## پیش‌نیازها

- Python 3.6 به بالا (نیاز به pip نداره)
- لینوکس (Ubuntu 18+، CentOS 7+، Debian 10+)
- برای ICMP ping باید root باشی — بقیه پروتکل‌ها بدون root هم کار می‌کنن

---

## نصب

### روش سریع (خودکار)

```bash
curl -O https://raw.githubusercontent.com/alixtron0/vscanner/main/install.sh
chmod +x install.sh
sudo bash install.sh
```

### روش دستی (توصیه‌شده برای سرورهای داخل ایران)

دانلود مستقیم روی سرورهای ایران اغلب مشکل داره — routing ناپایداره یا فیلتره. روش مطمئن‌تر اینه:

1. فایل `scanner.py` رو روی **لپ‌تاپ یا کامپیوتر خودت** دانلود کن
2. با `scp` به سرورت انتقال بده:

```bash
scp scanner.py root@IP_سرور_شما:/root/scanner.py
```

3. وارد سرور بشو و اجرا کن:

```bash
ssh root@IP_سرور_شما
python3 /root/scanner.py
```

همین. نیازی به هیچ مرحله نصب دیگه‌ای نیست.

---

## نحوه استفاده

**شروع اسکن (در پس‌زمینه اجرا می‌شه):**
```bash
python3 scanner.py
```

**چک کردن وضعیت اسکن:**
```bash
python3 scanner.py --status
```

**اجرا در foreground (برای debug):**
```bash
python3 scanner.py --foreground
```

---

## پروتکل‌های قابل انتخاب

موقع شروع اسکن می‌تونی یک یا چند پروتکل انتخاب کنی:

| شماره | پروتکل | چی بررسی می‌کنه |
|-------|---------|----------------|
| 1 | tcp80 | اتصال TCP روی پورت 80 |
| 2 | tcp443 | اتصال TCP روی پورت 443 |
| 3 | http | درخواست HTTP GET کامل |
| 4 | https | HTTPS GET (بدون بررسی certificate) |
| 5 | icmp | Ping واقعی (نیاز به root) |
| 6 | dns | زمان resolve شدن DNS |
| 7 | tls | TLS handshake کامل |

انتخاب چند پروتکل همزمان دقت میانگین latency رو بیشتر می‌کنه.

---

## فایل نتایج

نتایج به صورت پیش‌فرض در `~/vercel_scan_results.txt` ذخیره می‌شه و هر بار بازنویسی می‌شه:

```
cdn.cloudflare.net          avg=   12.3ms  [tcp443=11.2ms  https=13.4ms  dns=8.1ms]
vercel.com                  avg=   24.7ms  [tcp443=22.1ms  https=27.3ms  dns=14.2ms]
assets.vercel.com           avg=   31.0ms  [tcp443=28.5ms  https=33.4ms  dns=9.1ms]
```

---

## نکات مهم برای سرورهای ایران

- به جای `wget` یا `curl` داخل سرور، فایل رو با `scp` انتقال بده — خیلی مطمئن‌تره
- با root اجرا کن (`sudo`) تا ICMP هم فعال بشه — دقیق‌ترین اندازه‌گیری latency رو داره
- اگه روی خط سنگین فیلتر هستی، اول فقط TCP و DNS انتخاب کن — سریع‌تر تموم می‌شه
- اسکن در پس‌زمینه اجرا می‌شه، بعد از بستن SSH هم ادامه می‌ده
- برای VPS کم‌حافظه (512 مگابایت یا کمتر) وقتی پرسیده شد تعداد worker رو بین 32 تا 64 بذار

---

## فایل‌هایی که حین اجرا ساخته می‌شن

| فایل | کاربرد |
|------|--------|
| `/tmp/vercel_scan_status.json` | وضعیت زنده اسکن |
| `/tmp/vercel_scan.log` | لاگ پروسه پس‌زمینه |
| `~/vercel_scan_results.txt` | نتایج نهایی |

---

## لایسنس

MIT
