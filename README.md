# 🛡️ ATRIX OS - Cyber Security & OSINT Workstation

A browser-based Cyber Security & OSINT terminal operating system powered by React, Vite, Tailwind CSS, and an Express.js backend for real network intelligence.

---

## 🚀 Fitur Unggulan
* **OSINT & Reconnaissance**: `sherlock`, `gravatar`, `whois`, `subdomains`, `wayback`, `dork`, `email`, `phone`, `github`, `ghrepos`, `ghemail`.
* **Network & Security Auditing**: `techstack` (Wappalyzer-lite), `info` (deep website purpose & utility analyzer), `emailsec` (SPF, DMARC, DKIM), `headers` (HSTS, CSP, X-Frame), `cors`, `ssl`, `portscan`, `cve`, `crack` (rainbow dictionary hash recovery).
* **Linux Terminal Experience**: Virtual file system (`ls`, `cat`, `nano`, `grep`, `mkdir`, `rm`), Arch Linux aesthetic, neofetch system info, and customizable matrix theme.

---

## 💻 Cara Menjalankan di Lokal (PC / Laptop)

1. **Clone atau Extract ZIP project ini**:
   ```bash
   cd atrix-os
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Buat file `.env`**:
   Salin `.env.example` ke `.env`:
   ```bash
   cp .env.example .env
   ```
   *(Opsional) Isi `GEMINI_API_KEY` jika ingin fitur AI intelligence lebih pintar.*

4. **Jalankan server development**:
   ```bash
   npm run dev
   ```
   Buka browser di: `http://localhost:3000`

5. **Build untuk production**:
   ```bash
   npm run build
   npm start
   ```

---

## 🌐 Cara Deploy Gratis ke Render.com (Recommended)

1. Upload / Push folder project ini ke akun **GitHub** kamu.
2. Buka dashboard [Render.com](https://dashboard.render.com/) dan login.
3. Klik tombol **New +** -> pilih **Web Service**.
4. Hubungkan ke repository GitHub kamu.
5. Konfigurasi Service:
   * **Name**: `atrix-os`
   * **Runtime**: `Node`
   * **Build Command**: `npm install && npm run build`
   * **Start Command**: `npm start`
6. *(Opsional)* Pada bagian **Environment Variables**, tambahkan:
   * `NODE_ENV` = `production`
   * `PORT` = `3000`
   * `GEMINI_API_KEY` = (API key Gemini kamu dari Google AI Studio)
7. Klik **Create Web Service**.
8. Tunggu proses build selesai (sekitar 1-2 menit) -> Website ATRIX OS kamu sudah live dengan HTTPS gratis!

---

## ☁️ Cara Deploy ke Railway.app atau VPS Linux

### Railway:
1. Hubungkan GitHub repo ke [Railway.app](https://railway.app/).
2. Railway akan otomatis mendeteksi Node.js.
3. Masukkan Environment Variable `PORT=3000`.

### VPS Ubuntu (DigitalOcean / IDCloudHost):
```bash
git clone <repo-url>
cd atrix-os
npm install
npm run build
# Jalankan menggunakan PM2
npm install -g pm2
pm2 start "npm start" --name atrix-os
```
Setup Nginx reverse proxy ke port 3000 dan pasang Certbot SSL.

---
Dikembangkan untuk Whitehat & Ethical Security Enthusiasts.
