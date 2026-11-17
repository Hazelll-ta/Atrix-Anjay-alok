# ATRIX OS — Cyber Security, OSINT & CLI Toolkit

Workstation OSINT & Cyber Security real-time yang bisa dijalankan di **Vercel (Web 100% Gratis)**, **Termux CLI (Android)**, maupun **Server Node.js lokal/VPS**.

---

## 1. Cara Deploy Gratis 100% ke Vercel (Tanpa Kartu Kredit)

1. Upload seluruh file project ini ke repository **GitHub** (Private/Public).
2. Buka **[vercel.com](https://vercel.com/)** -> Login dengan GitHub -> **Add New Project** -> pilih repo tadi.
3. Konfigurasi otomatis terbaca dari `vercel.json` (`Build Command: npm run build`, `Output Directory: dist`).
4. *(Opsional)* Tambahkan Environment Variable `GEMINI_API_KEY` jika ingin fitur `ai` & ringkasan cerdas aktif.
5. Klik **Deploy** -> selesai! Semua fitur (`urlscan`, `intel`, `nmap`, `info`, `sqlmap`, `ssl`, `headers`, `whois`, `subdomains`, `sherlock`, `cve`, dll.) langsung aktif dengan HTTPS & bebas pasang custom domain gratis.

---

## 2. Cara Paling Cepat di Termux (Termasuk Termux Play Store — Tanpa `npm install`)

File **`atrix-cli.mjs`** sudah dibundel menjadi 1 file JS mandiri tanpa butuh `node_modules` atau binary native:

```bash
pkg update && pkg install nodejs unzip -y
termux-setup-storage

unzip ~/storage/downloads/atrix-os-complete.zip -d ~/atrix-os
cd ~/atrix-os

node atrix-cli.mjs
```

Atau satu perintah langsung:
```bash
node atrix-cli.mjs urlscan https://example.com
node atrix-cli.mjs intel 1.1.1.1
```

---

## 3. Mode Developer Lokal
```bash
npm install
npm run cli       # Jalankan dari source cli.ts
npm run build:cli # Rebuild atrix-cli.mjs
npm run dev       # Jalankan web server (http://localhost:3000)
```
