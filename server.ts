import crypto from 'crypto';
import fs from 'fs';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dns from 'dns/promises';
import tls from 'tls';
import net from 'net';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config({ quiet: true });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isProd = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;

export const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- API Endpoints for Real Working Tools ---

function isPrivateOrBogonIp(ip: string): boolean {
  if (!ip) return true;
  const clean = ip.replace(/^::ffff:/i, '').trim();
  if (clean === '::1' || clean === 'localhost') return true;
  if (/^(10\.|127\.|169\.254\.|192\.168\.|0\.)/.test(clean)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(clean)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(clean)) return true; // CGNAT 100.64.0.0/10
  if (/^(fc|fd|fe80:)/i.test(clean)) return true; // IPv6 ULA / link-local
  return false;
}

async function fetchJsonSafe(url: string, timeoutMs = 3500): Promise<any | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'ATRIX-GeoIP-Engine/2.0',
        'Accept': 'application/json'
      }
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function resolveDeepIpGeo(rawIp?: string) {
  const cleanIp = rawIp ? rawIp.replace(/^::ffff:/i, '').trim() : '';
  const isBogon = cleanIp ? isPrivateOrBogonIp(cleanIp) : false;

  if (cleanIp && isBogon) {
    return {
      ip: cleanIp,
      ipVersion: net.isIPv6(cleanIp) ? 'IPv6' : 'IPv4',
      isBogon: true,
      continent: 'Local / Private Network',
      country: 'Private Network (RFC 1918 / Loopback)',
      country_code: 'LAN',
      region: 'Internal Routing',
      city: 'Localhost / LAN',
      postal: 'N/A',
      org: 'Private / Non-Routable IP Block',
      isp: 'Internal Network',
      asn: 'N/A',
      bgpPrefix: 'Private CIDR',
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
      latitude: undefined as number | undefined,
      longitude: undefined as number | undefined,
      networkType: 'Private / Internal Network',
      securityFlags: { isProxy: false, isHosting: false, isMobile: false, isAnycast: false, isBogon: true },
      consensus: 'Local RFC 1918 / Loopback address',
      providersUsed: ['Local Validator'],
      providerBreakdown: [] as { provider: string; city: string; country: string; org: string }[],
      reverseDns: [] as string[]
    };
  }

  // Empty cleanIp -> auto-detect server/egress public IP; otherwise query target IP across 5 live engines in parallel
  const ipApiUrl = cleanIp
    ? `http://ip-api.com/json/${encodeURIComponent(cleanIp)}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,zip,lat,lon,timezone,offset,isp,org,as,asname,reverse,mobile,proxy,hosting,query`
    : 'http://ip-api.com/json/?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,zip,lat,lon,timezone,offset,isp,org,as,asname,reverse,mobile,proxy,hosting,query';
  const ipWhoUrl = cleanIp ? `https://ipwho.is/${encodeURIComponent(cleanIp)}` : 'https://ipwho.is/';
  const ipInfoUrl = cleanIp ? `https://ipinfo.io/${encodeURIComponent(cleanIp)}/json` : 'https://ipinfo.io/json';
  const ipApiCoUrl = cleanIp ? `https://ipapi.co/${encodeURIComponent(cleanIp)}/json/` : 'https://ipapi.co/json/';
  const ripeUrl = cleanIp ? `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(cleanIp)}` : '';

  const [ipApiRes, ipWhoRes, ipInfoRes, ipApiCoRes, ripeRes] = await Promise.all([
    fetchJsonSafe(ipApiUrl, 3500),
    fetchJsonSafe(ipWhoUrl, 3500),
    fetchJsonSafe(ipInfoUrl, 3500),
    fetchJsonSafe(ipApiCoUrl, 2500),
    ripeUrl ? fetchJsonSafe(ripeUrl, 3200) : Promise.resolve(null)
  ]);

  const ipApi = ipApiRes?.status === 'success' ? ipApiRes : null;
  const ipWho = ipWhoRes?.success === true ? ipWhoRes : null;
  const ipInfo = ipInfoRes?.ip && !ipInfoRes?.error ? ipInfoRes : null;
  const ipApiCo = ipApiCoRes?.ip && !ipApiCoRes?.error ? ipApiCoRes : null;
  const ripeData = ripeRes?.status === 'ok' && ripeRes?.data ? ripeRes.data : null;

  const detectedIp = cleanIp || ipApi?.query || ipWho?.ip || ipInfo?.ip || ipApiCo?.ip || '127.0.0.1';

  // Parse ipinfo loc ("lat,lon")
  let infoLat: number | undefined;
  let infoLon: number | undefined;
  if (typeof ipInfo?.loc === 'string' && ipInfo.loc.includes(',')) {
    const [la, lo] = ipInfo.loc.split(',').map((s: string) => parseFloat(s.trim()));
    if (Number.isFinite(la) && Number.isFinite(lo)) {
      infoLat = la;
      infoLon = lo;
    }
  }

  // Extract ASN cleanly
  let asn = 'N/A';
  if (ipApi?.as) {
    asn = String(ipApi.as).split(' ')[0];
  } else if (ipWho?.connection?.asn) {
    asn = `AS${ipWho.connection.asn}`;
  } else if (ipInfo?.org && /^AS\d+/i.test(ipInfo.org)) {
    asn = ipInfo.org.split(' ')[0];
  } else if (ipApiCo?.asn) {
    asn = String(ipApiCo.asn);
  } else if (Array.isArray(ripeData?.asns) && ripeData.asns.length > 0) {
    asn = `AS${ripeData.asns[0]}`;
  }

  const city = ipApi?.city || ipWho?.city || ipInfo?.city || ipApiCo?.city || 'Unknown';
  const region = ipApi?.regionName || ipWho?.region || ipInfo?.region || ipApiCo?.region || 'Unknown';
  const country = ipApi?.country || ipWho?.country || ipApiCo?.country_name || ipInfo?.country || 'Unknown';
  const country_code = ipApi?.countryCode || ipWho?.country_code || ipInfo?.country || ipApiCo?.country_code || 'N/A';
  const continent = ipApi?.continent || ipWho?.continent || ipApiCo?.continent_code || 'Unknown';
  const postal = ipApi?.zip || ipWho?.postal || ipInfo?.postal || ipApiCo?.postal || 'N/A';
  const isp = ipApi?.isp || ipWho?.connection?.isp || ipApiCo?.org || 'ISP Network';
  const org = ipApi?.org || ipWho?.connection?.org || (ipInfo?.org ? ipInfo.org.replace(/^AS\d+\s+/i, '') : '') || ipApiCo?.org || isp;
  const timezone = ipApi?.timezone || ipWho?.timezone?.id || ipInfo?.timezone || ipApiCo?.timezone || 'UTC';
  const latitude: number | undefined = ipApi?.lat ?? ipWho?.latitude ?? infoLat ?? ipApiCo?.latitude;
  const longitude: number | undefined = ipApi?.lon ?? ipWho?.longitude ?? infoLon ?? ipApiCo?.longitude;
  const bgpPrefix: string = ripeData?.prefix || 'N/A';

  const isAnycast = Boolean(ipInfo?.anycast);
  const isProxy = Boolean(ipApi?.proxy);
  const orgLower = `${isp} ${org}`.toLowerCase();
  const isHosting = Boolean(ipApi?.hosting) || /cloud|hosting|datacenter|amazon|aws|google|microsoft|azure|digitalocean|linode|vultr|ovh|hetzner|cloudflare|akamai|fastly/i.test(orgLower);
  const isMobile = Boolean(ipApi?.mobile);

  let networkType = 'Residential / Business ISP';
  if (isAnycast) networkType = 'Anycast / Global Edge / CDN';
  else if (isProxy) networkType = 'Proxy / VPN / Anonymizer Exit';
  else if (isHosting) networkType = 'Hosting / Cloud / Datacenter';
  else if (isMobile) networkType = 'Mobile Cellular Carrier';

  const providerBreakdown: { provider: string; city: string; country: string; org: string }[] = [];
  const providersUsed: string[] = [];
  if (ipApi) {
    providersUsed.push('ip-api.com');
    providerBreakdown.push({ provider: 'ip-api', city: ipApi.city || 'N/A', country: ipApi.countryCode || 'N/A', org: ipApi.isp || ipApi.org || 'N/A' });
  }
  if (ipWho) {
    providersUsed.push('ipwho.is');
    providerBreakdown.push({ provider: 'ipwho.is', city: ipWho.city || 'N/A', country: ipWho.country_code || 'N/A', org: ipWho.connection?.isp || ipWho.connection?.org || 'N/A' });
  }
  if (ipInfo) {
    providersUsed.push('ipinfo.io');
    providerBreakdown.push({ provider: 'ipinfo.io', city: ipInfo.city || 'N/A', country: ipInfo.country || 'N/A', org: ipInfo.org || 'N/A' });
  }
  if (ipApiCo) {
    providersUsed.push('ipapi.co');
    providerBreakdown.push({ provider: 'ipapi.co', city: ipApiCo.city || 'N/A', country: ipApiCo.country_code || 'N/A', org: ipApiCo.org || 'N/A' });
  }
  if (ripeData) {
    providersUsed.push('RIPE Stat BGP');
  }

  // Cross-provider consensus calculation
  const geoCountries = providerBreakdown.map(p => p.country.toUpperCase()).filter(c => c && c !== 'N/A');
  const geoCities = providerBreakdown.map(p => p.city.toLowerCase()).filter(c => c && c !== 'n/a' && c !== 'unknown');
  const uniqueCountries = new Set(geoCountries);
  const uniqueCities = new Set(geoCities);

  let consensus = 'Single/Fallback Source';
  if (providerBreakdown.length >= 2) {
    if (uniqueCountries.size === 1 && uniqueCities.size === 1) {
      consensus = `High Confidence (${providerBreakdown.length}/${providerBreakdown.length} GeoIP providers match city & country)`;
    } else if (uniqueCountries.size === 1) {
      consensus = isAnycast
        ? `Anycast Multi-PoP (${providerBreakdown.length} providers agree on ${country}; PoP cities vary)`
        : `Country Verified (${providerBreakdown.length}/${providerBreakdown.length} agree on ${country}; city varies across PoPs)`;
    } else {
      consensus = `Multi-Region Variance (${Array.from(uniqueCountries).join(' / ')})`;
    }
  }

  let reverseDns: string[] = [];
  try {
    if (detectedIp && !isPrivateOrBogonIp(detectedIp)) {
      reverseDns = await dns.reverse(detectedIp);
    }
  } catch {}
  if (reverseDns.length === 0 && ipInfo?.hostname) {
    reverseDns = [ipInfo.hostname];
  } else if (reverseDns.length === 0 && ipApi?.reverse) {
    reverseDns = [ipApi.reverse];
  }

  const hasCoords = typeof latitude === 'number' && typeof longitude === 'number';
  const osmUrl = hasCoords ? `https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=11/${latitude}/${longitude}` : undefined;
  const mapsUrl = hasCoords ? `https://maps.google.com/?q=${latitude},${longitude}` : undefined;

  return {
    ip: detectedIp,
    ipVersion: net.isIPv6(detectedIp) ? 'IPv6' : 'IPv4',
    isBogon: false,
    continent,
    country,
    country_code,
    region,
    city,
    postal,
    isp,
    org,
    asn,
    bgpPrefix,
    timezone,
    latitude,
    longitude,
    coordinates: hasCoords ? `${latitude}, ${longitude}` : undefined,
    osmUrl,
    mapsUrl,
    networkType,
    securityFlags: {
      isProxy,
      isHosting,
      isMobile,
      isAnycast,
      isBogon: false
    },
    consensus,
    providersUsed,
    providerBreakdown,
    reverseDns
  };
}

// 1. IP and Network Details (Supports client self-inspection or target domain/IP query)
app.all('/api/ip', async (req, res) => {
  try {
    const queryTarget = (req.query.target as string) || (req.body?.target as string) || '';
    let targetIp = '';
    let isRemoteTarget = false;
    let resolvedAddresses: string[] = [];

    if (queryTarget) {
      isRemoteTarget = true;
      const cleanTarget = queryTarget.replace(/^https?:\/\//, '').split('/')[0].split('?')[0].trim();
      const hostOnly = cleanTarget.startsWith('[')
        ? cleanTarget.slice(1, cleanTarget.indexOf(']'))
        : (net.isIP(cleanTarget) ? cleanTarget : cleanTarget.split(':')[0]);

      if (net.isIP(hostOnly)) {
        targetIp = hostOnly;
        resolvedAddresses = [hostOnly];
      } else {
        const [v4, v6] = await Promise.all([
          dns.resolve4(hostOnly).catch(() => [] as string[]),
          dns.resolve6(hostOnly).catch(() => [] as string[])
        ]);
        resolvedAddresses = [...v4, ...v6];
        if (resolvedAddresses.length > 0) {
          targetIp = resolvedAddresses[0];
        } else {
          const fallback = await dns.lookup(hostOnly).catch(() => null);
          if (!fallback) {
            return res.status(404).json({ error: `Host '${hostOnly}' tidak dapat di-resolve ke alamat IP.` });
          }
          targetIp = fallback.address;
          resolvedAddresses = [fallback.address];
        }
      }
    }

    let queryIp = targetIp;
    if (!isRemoteTarget) {
      const forwarded = req.headers['x-forwarded-for'];
      const clientIp = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : req.socket.remoteAddress || '';
      // Only pass clientIp to external GeoIP providers if it's a real public IP (not localhost/internal)
      if (clientIp && !isPrivateOrBogonIp(clientIp)) {
        queryIp = clientIp.replace(/^::ffff:/i, '');
      }
    }

    const geo = await resolveDeepIpGeo(queryIp || undefined);

    res.json({
      ...geo,
      target: queryTarget || undefined,
      isRemoteTarget,
      resolvedAddresses: resolvedAddresses.length > 0 ? resolvedAddresses : [geo.ip],
      userAgent: req.headers['user-agent'] || 'Unknown'
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to detect IP geolocation' });
  }
});

// 2. Real cURL / HTTP Fetcher (bypass browser CORS)
app.post('/api/curl', async (req, res) => {
  const { url, method = 'GET', headers = {}, body } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  let targetUrl = url;
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000);

    const fetchOptions: RequestInit = {
      method: method.toUpperCase(),
      headers: {
        'User-Agent': 'ATRIX-Terminal/1.0 (curl-compatible)',
        ...headers
      },
      signal: controller.signal,
      redirect: 'follow'
    };

    if (body && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(fetchOptions.method || '')) {
      fetchOptions.body = typeof body === 'object' ? JSON.stringify(body) : String(body);
      if (!headers['Content-Type'] && !headers['content-type']) {
        (fetchOptions.headers as any)['Content-Type'] = 'application/json';
      }
    }

    const response = await fetch(targetUrl, fetchOptions);
    clearTimeout(timeoutId);

    const elapsed = Date.now() - startTime;
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((val, key) => {
      responseHeaders[key] = val;
    });

    const textData = await response.text();
    let jsonData = null;
    try {
      jsonData = JSON.parse(textData);
    } catch {
      // plain text
    }

    res.json({
      status: response.status,
      statusText: response.statusText,
      timeMs: elapsed,
      headers: responseHeaders,
      data: jsonData !== null ? jsonData : textData,
      isJson: jsonData !== null,
      size: Buffer.byteLength(textData, 'utf8')
    });
  } catch (err: any) {
    const elapsed = Date.now() - startTime;
    res.status(502).json({
      error: err.name === 'AbortError' ? 'Request timed out after 12s' : (err.message || 'Connection failed'),
      timeMs: elapsed
    });
  }
});

// Security Defense: HTTP Security Headers Audit
app.post('/api/security/headers', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  let targetUrl = url;
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const response = await fetch(targetUrl, {
      method: 'HEAD',
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-SecurityAudit/1.0' }
    });
    clearTimeout(timeout);

    const headers: Record<string, string> = {};
    response.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

    const checks = [
      {
        name: 'Strict-Transport-Security (HSTS)',
        header: 'strict-transport-security',
        present: !!headers['strict-transport-security'],
        value: headers['strict-transport-security'] || null,
        desc: 'Enforces HTTPS encryption and prevents downgrade attacks.',
        weight: 25
      },
      {
        name: 'Content-Security-Policy (CSP)',
        header: 'content-security-policy',
        present: !!headers['content-security-policy'],
        value: headers['content-security-policy'] || null,
        desc: 'Mitigates Cross-Site Scripting (XSS) and data injection.',
        weight: 25
      },
      {
        name: 'X-Frame-Options',
        header: 'x-frame-options',
        present: !!headers['x-frame-options'],
        value: headers['x-frame-options'] || null,
        desc: 'Prevents Clickjacking attacks by disallowing iframing.',
        weight: 15
      },
      {
        name: 'X-Content-Type-Options',
        header: 'x-content-type-options',
        present: headers['x-content-type-options'] === 'nosniff',
        value: headers['x-content-type-options'] || null,
        desc: 'Prevents MIME-sniffing vulnerabilities.',
        weight: 15
      },
      {
        name: 'Referrer-Policy',
        header: 'referrer-policy',
        present: !!headers['referrer-policy'],
        value: headers['referrer-policy'] || null,
        desc: 'Controls how much referrer information is sent with requests.',
        weight: 10
      },
      {
        name: 'Permissions-Policy',
        header: 'permissions-policy',
        present: !!headers['permissions-policy'],
        value: headers['permissions-policy'] || null,
        desc: 'Restricts sensitive browser APIs (camera, geolocation, mic).',
        weight: 10
      }
    ];

    let score = 0;
    checks.forEach(c => {
      if (c.present) score += c.weight;
    });

    let grade = 'F';
    if (score >= 90) grade = 'A+';
    else if (score >= 80) grade = 'A';
    else if (score >= 65) grade = 'B';
    else if (score >= 50) grade = 'C';
    else if (score >= 35) grade = 'D';

    res.json({
      url: targetUrl,
      score,
      grade,
      checks,
      server: headers['server'] || 'Undisclosed'
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to inspect headers' });
  }
});

// Security Defense: SSL/TLS Certificate Audit
app.post('/api/security/ssl', (req, res) => {
  const { host } = req.body;
  if (!host) return res.status(400).json({ error: 'Host is required' });

  const cleanHost = host.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  const socket = tls.connect({
    host: cleanHost,
    port: 443,
    servername: cleanHost,
    timeout: 5000
  }, () => {
    const cert = socket.getPeerCertificate(true);
    const protocol = socket.getProtocol();
    const cipher = socket.getCipher();
    socket.destroy();

    if (!cert || Object.keys(cert).length === 0) {
      return res.status(400).json({ error: 'No certificate received' });
    }

    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);
    const now = new Date();
    const daysRemaining = Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

    res.json({
      host: cleanHost,
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      daysRemaining,
      isExpired: daysRemaining <= 0,
      protocol,
      cipher: cipher.name,
      fingerprint256: cert.fingerprint256,
      subjectAltNames: cert.subjectaltname || 'None'
    });
  });

  socket.on('error', (err) => {
    socket.destroy();
    res.status(500).json({ error: err.message || 'TLS connection failed' });
  });

  socket.on('timeout', () => {
    socket.destroy();
    res.status(504).json({ error: 'TLS connection timed out' });
  });
});

// Deep URL Security Scanner (Redirect Tracer, Phishing Heuristics, SSL/TLS, Headers & HTML Audit)
const urlScanRateLimits = new Map<string, { count: number; resetTime: number }>();

function isPrivateOrReservedIp(ipAddr: string): boolean {
  let clean = ipAddr.trim().toLowerCase();
  if (clean.startsWith('::ffff:')) {
    clean = clean.slice(7);
  }
  if (net.isIPv4(clean)) {
    const parts = clean.split('.').map(Number);
    if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return true;
    const [a, b, c] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 169 && b === 254) return true; // Link-local / Cloud Metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 0 && c === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true; // Multicast & Reserved
    return false;
  }
  if (net.isIPv6(clean)) {
    if (clean === '::1' || clean === '::' || clean === '0:0:0:0:0:0:0:1') return true;
    if (clean.startsWith('fc') || clean.startsWith('fd')) return true; // Unique local
    if (/^fe[89ab]/.test(clean)) return true; // Link-local
    if (clean.startsWith('ff')) return true; // Multicast
    return false;
  }
  return true;
}

async function validatePublicUrlTarget(rawUrl: string): Promise<{ parsed: URL; resolvedIps: string[] }> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Format URL tidak valid.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Protokol '${parsed.protocol}' tidak didukung. Hanya http:// atau https:// yang diizinkan.`);
  }

  const host = parsed.hostname.toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.localhost')) {
    throw new Error(`Host internal/lokal '${host}' diblokir demi keamanan (SSRF Protection).`);
  }

  if (net.isIP(host)) {
    if (isPrivateOrReservedIp(host)) {
      throw new Error(`Alamat IP privat/internal '${host}' diblokir demi keamanan (SSRF Protection).`);
    }
    return { parsed, resolvedIps: [host] };
  }

  const records = await dns.lookup(host, { all: true });
  if (!records || records.length === 0) {
    throw new Error(`Domain '${host}' gagal di-resolve melalui DNS (NXDOMAIN).`);
  }
  for (const rec of records) {
    if (isPrivateOrReservedIp(rec.address)) {
      throw new Error(`Domain '${host}' mengarah ke IP internal '${rec.address}' dan diblokir (SSRF Protection).`);
    }
  }
  return { parsed, resolvedIps: records.map(r => r.address) };
}

app.post('/api/security/urlscan', async (req, res) => {
  const forwarded = req.headers['x-forwarded-for'];
  const clientIp = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : req.socket.remoteAddress || '127.0.0.1';

  const now = Date.now();
  const rl = urlScanRateLimits.get(clientIp);
  if (rl && now < rl.resetTime) {
    if (rl.count >= 40) {
      return res.status(429).json({ error: 'Rate limit: maksimal 40 scan URL per menit.' });
    }
    rl.count++;
  } else {
    urlScanRateLimits.set(clientIp, { count: 1, resetTime: now + 60000 });
  }

  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL wajib diisi.' });
  }

  let normalizedInput = url.trim();
  if (!normalizedInput || normalizedInput.length > 2048) {
    return res.status(400).json({ error: 'Panjang URL tidak valid (maksimal 2048 karakter).' });
  }
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(normalizedInput)) {
    normalizedInput = `https://${normalizedInput}`;
  }

  const startTime = Date.now();
  const findings: { severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'; category: string; title: string; detail: string }[] = [];
  const recommendations: string[] = [];
  let riskScore = 0;

  try {
    const initialValidation = await validatePublicUrlTarget(normalizedInput);
    const initialUrl = initialValidation.parsed;
    const initialHost = initialUrl.hostname.toLowerCase();

    // 1. Static / Lexical URL Anomaly Checks
    if (initialUrl.username || initialUrl.password || normalizedInput.includes('@')) {
      const beforePath = normalizedInput.split('?')[0].split('#')[0];
      if (beforePath.includes('@')) {
        riskScore += 35;
        findings.push({
          severity: 'HIGH',
          category: 'Phishing Trick',
          title: 'Embedded Userinfo (@) Terdeteksi di URL',
          detail: 'Karakter "@" sebelum domain sering dipakai penipu untuk menyamarkan domain asli (misal https://google.com@evil.com).'
        });
      }
    }

    if (initialHost.includes('xn--')) {
      riskScore += 30;
      findings.push({
        severity: 'HIGH',
        category: 'Homograph / Punycode',
        title: 'Domain Punycode (IDN) Terdeteksi',
        detail: `Hostname '${initialHost}' menggunakan prefix 'xn--' yang berpotensi menyamar sebagai huruf Latin domain resmi (IDN homograph attack).`
      });
    }

    if (net.isIP(initialHost)) {
      riskScore += 25;
      findings.push({
        severity: 'MEDIUM',
        category: 'Host Anomaly',
        title: 'URL Menggunakan IP Mentah Tanpa Domain',
        detail: `Mengakses web langsung via IP (${initialHost}) sering ditemukan pada C2 server, phishing darurat, atau server tanpa domain valid.`
      });
    }

    if (initialUrl.port && initialUrl.port !== '80' && initialUrl.port !== '443') {
      riskScore += 15;
      findings.push({
        severity: 'LOW',
        category: 'Port Anomaly',
        title: `Menggunakan Port Non-Standar (:${initialUrl.port})`,
        detail: `Lalu lintas web umumnya berjalan di port 80/443; port :${initialUrl.port} bisa menandakan panel admin terekspos atau layanan staging.`
      });
    }

    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 's.id', 'is.gd', 'rb.gy', 'shorturl.at', 'ow.ly', 'goo.gl', 'tiny.cc', 'rebrand.ly', 't.ly', 'short.gy'];
    const isShortener = shorteners.some(s => initialHost === s || initialHost.endsWith(`.${s}`));
    if (isShortener) {
      riskScore += 15;
      findings.push({
        severity: 'MEDIUM',
        category: 'Link Obfuscation',
        title: 'URL Shortener Terdeteksi',
        detail: `Domain '${initialHost}' adalah pemendek tautan. Tujuan asli disembunyikan hingga redirect ditelusuri.`
      });
    }

    // Check query params for sensitive tokens or open redirects
    const sensitiveParams = ['token', 'access_token', 'auth', 'apikey', 'api_key', 'key', 'secret', 'password', 'passwd', 'pwd', 'session', 'sid', 'jwt'];
    const openRedirectParams = ['redirect', 'redirect_uri', 'redirect_url', 'next', 'url', 'target', 'dest', 'destination', 'return', 'returnurl', 'continue', 'redir', 'goto'];

    for (const [k, v] of initialUrl.searchParams.entries()) {
      const kl = k.toLowerCase();
      if (sensitiveParams.includes(kl) || /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(v)) {
        riskScore += 25;
        findings.push({
          severity: 'HIGH',
          category: 'Data Exposure',
          title: `Potensi Kebocoran Kredensial/Token di Query Parameter ('${k}')`,
          detail: 'Token/secret di URL tercatat pada history browser, proxy, server log, dan header Referer pihak ketiga.'
        });
      }
      if (openRedirectParams.includes(kl) && /^https?:\/\//i.test(v)) {
        try {
          const redirTarget = new URL(v);
          if (redirTarget.hostname.toLowerCase() !== initialHost) {
            riskScore += 20;
            findings.push({
              severity: 'MEDIUM',
              category: 'Open Redirect',
              title: `Parameter Redirect Eksternal Terdeteksi ('${k}' -> ${redirTarget.hostname})`,
              detail: 'Parameter pengalihan ke domain lain rawan disalahgunakan untuk serangan Open Redirect / phishing berbuntut domain terpercaya.'
            });
          }
        } catch {}
      }
      if (/<[a-z!/][^>]*>/i.test(v) || /(?:javascript|vbscript):|data:text\/html/i.test(v) || /\bon(?:error|load|click|mouseover|focus)\s*=/i.test(v)) {
        riskScore += 30;
        findings.push({
          severity: 'HIGH',
          category: 'HTML/XSS Lure in URL',
          title: `Potensi Indikasi HTML Injection / Reflected XSS di Parameter ('${k}')`,
          detail: 'Nilai parameter URL mengandung fragmen tag HTML, event handler, atau skema javascript:/data:. Tautan ini mencurigakan dan berisiko menjadi umpan XSS.'
        });
      }
    }

    if (initialUrl.hash && (/<[a-z!/][^>]*>/i.test(decodeURIComponent(initialUrl.hash)) || /(?:javascript|vbscript):/i.test(initialUrl.hash))) {
      riskScore += 25;
      findings.push({
        severity: 'HIGH',
        category: 'DOM XSS Lure in Fragment',
        title: 'Fragmen Hash (#) URL Mengandung Fragmen HTML/Script',
        detail: 'Hash URL berisi pola tag HTML atau skema javascript: yang sering muncul pada tautan umpan DOM XSS.'
      });
    }

    // Check dangerous file extensions in pathname
    const lowerPath = initialUrl.pathname.toLowerCase();
    const riskyExts = ['.exe', '.apk', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.msi', '.dmg', '.iso', '.jar', '.hta'];
    const matchedExt = riskyExts.find(ext => lowerPath.endsWith(ext));
    if (matchedExt) {
      riskScore += 35;
      findings.push({
        severity: 'HIGH',
        category: 'Payload / Malware Risk',
        title: `URL Mengarah Langsung ke File Eksekutabel (${matchedExt})`,
        detail: `Tautan mengunduh file biner/installer '${matchedExt}'. Pastikan integritas dan sumber file sebelum dieksekusi.`
      });
    }

    // 2. Live Redirect Chain Tracer (up to 8 hops)
    const redirectChain: { step: number; url: string; status: number; location?: string }[] = [];
    let currentUrl = initialUrl.toString();
    let finalResponse: Response | null = null;
    let finalIps = initialValidation.resolvedIps;
    let fetchError: string | null = null;

    for (let hop = 1; hop <= 8; hop++) {
      try {
        const hopValidation = hop === 1 ? initialValidation : await validatePublicUrlTarget(currentUrl);
        finalIps = hopValidation.resolvedIps;

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 7000);
        const resp = await fetch(currentUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; ATRIX-URLScanner/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'
          }
        });
        clearTimeout(timer);

        const locationHeader = resp.headers.get('location');
        redirectChain.push({
          step: hop,
          url: currentUrl,
          status: resp.status,
          location: locationHeader || undefined
        });

        if (resp.status >= 300 && resp.status < 400 && locationHeader) {
          const nextUrl = new URL(locationHeader, currentUrl).toString();
          // Cancel body before following
          try { await resp.body?.cancel(); } catch {}
          if (redirectChain.some(r => r.url === nextUrl)) {
            riskScore += 20;
            findings.push({
              severity: 'MEDIUM',
              category: 'Redirect Loop',
              title: 'Terdeteksi Redirect Loop',
              detail: `URL berputar kembali ke '${nextUrl}' dan gagal mencapai halaman akhir.`
            });
            break;
          }
          currentUrl = nextUrl;
          continue;
        }

        finalResponse = resp;
        break;
      } catch (err: any) {
        fetchError = err?.name === 'AbortError' ? 'Connection timeout (>7 detik)' : (err?.message || 'Koneksi gagal');
        break;
      }
    }

    const finalParsed = new URL(currentUrl);
    const finalHost = finalParsed.hostname.toLowerCase();

    if (finalParsed.protocol === 'http:') {
      riskScore += 25;
      findings.push({
        severity: 'HIGH',
        category: 'Transport Security',
        title: 'Menggunakan HTTP Tanpa Enkripsi (Tidak Aman)',
        detail: `Tujuan akhir (${finalHost}) berjalan di HTTP plaintext, rentan terhadap penyadapan (MITM) dan injeksi skrip ISP/WiFi publik.`
      });
    }

    if (initialUrl.protocol === 'https:' && finalParsed.protocol === 'http:') {
      riskScore += 20;
      findings.push({
        severity: 'HIGH',
        category: 'SSL Downgrade',
        title: 'Terjadi Downgrade dari HTTPS ke HTTP',
        detail: 'Tautan awal memakai HTTPS namun dialihkan turun ke HTTP tidak terenkripsi.'
      });
    }

    if (initialHost !== finalHost && !finalHost.endsWith(`.${initialHost}`) && !initialHost.endsWith(`.${finalHost}`)) {
      riskScore += isShortener ? 10 : 20;
      findings.push({
        severity: 'MEDIUM',
        category: 'Cross-Domain Redirect',
        title: `Dialihkan ke Domain Berbeda (${initialHost} -> ${finalHost})`,
        detail: `URL awal berpindah ke domain lain '${finalHost}'. Pastikan domain akhir memang tujuan yang diharapkan.`
      });
    }

    // Suspicious phishing keywords check on final host
    const brandKeywords = ['whatsapp', 'dana', 'bca', 'bri', 'mandiri', 'bni', 'gopay', 'ovo', 'shopee', 'tokopedia', 'paypal', 'google', 'apple', 'microsoft', 'binance', 'metamask', 'instagram', 'facebook'];
    const suspiciousWords = ['login', 'verify', 'secure', 'update', 'claim', 'hadiah', 'bonus', 'otp', 'kaget', 'giveaway', 'support'];
    const officialAllowMap: Record<string, string[]> = {
      whatsapp: ['whatsapp.com', 'wa.me'],
      google: ['google.com', 'youtu.be', 'youtube.com', 'googleapis.com'],
      paypal: ['paypal.com'],
      apple: ['apple.com', 'icloud.com'],
      microsoft: ['microsoft.com', 'live.com', 'office.com'],
      instagram: ['instagram.com'],
      facebook: ['facebook.com', 'fb.com'],
      shopee: ['shopee.co.id', 'shopee.com'],
      tokopedia: ['tokopedia.com'],
      bca: ['bca.co.id', 'klikbca.com'],
      bri: ['bri.co.id'],
      mandiri: ['bankmandiri.co.id'],
      bni: ['bni.co.id'],
      dana: ['dana.id'],
      gopay: ['gopay.co.id', 'gojek.com'],
      ovo: ['ovo.id'],
      binance: ['binance.com'],
      metamask: ['metamask.io']
    };

    for (const brand of brandKeywords) {
      if (finalHost.includes(brand)) {
        const allowed = officialAllowMap[brand] || [];
        const isOfficial = allowed.some(dom => finalHost === dom || finalHost.endsWith(`.${dom}`));
        if (!isOfficial) {
          riskScore += 40;
          findings.push({
            severity: 'CRITICAL',
            category: 'Brand Impersonation',
            title: `Indikasi Penyamaran Merek '${brand.toUpperCase()}' pada Domain '${finalHost}'`,
            detail: `Hostname mengandung kata '${brand}' tetapi BUKAN domain resmi (${allowed.join(', ')}). Sangat kuat mengarah ke situs phishing/penipuan.`
          });
          break;
        }
      }
    }

    const fullLower = currentUrl.toLowerCase();
    const hitSuspicious = suspiciousWords.filter(w => fullLower.includes(w));
    if (hitSuspicious.length >= 2 && finalHost.split('.').length >= 3) {
      riskScore += 15;
      findings.push({
        severity: 'MEDIUM',
        category: 'Phishing Heuristic',
        title: `Kombinasi Kata Mencurigakan di URL (${hitSuspicious.slice(0, 4).join(', ')})`,
        detail: 'URL memadukan beberapa kata bertema verifikasi/hadiah/login dengan struktur subdomain bertingkat.'
      });
    }

    // 3. TLS Certificate Inspection on Final HTTPS Host
    let tlsInfo: any = null;
    if (finalParsed.protocol === 'https:') {
      try {
        tlsInfo = await new Promise((resolve) => {
          const portNum = finalParsed.port ? parseInt(finalParsed.port, 10) : 443;
          const sock = tls.connect(
            {
              host: finalHost,
              port: portNum,
              servername: finalHost,
              rejectUnauthorized: false,
              timeout: 4500
            },
            () => {
              const cert = sock.getPeerCertificate();
              const authorized = sock.authorized;
              const authError = sock.authorizationError;
              const protocol = sock.getProtocol();
              sock.end();
              if (!cert || !cert.subject) {
                return resolve({ error: 'Tidak ada sertifikat TLS yang disajikan server.' });
              }
              const validToDate = new Date(cert.valid_to);
              const daysRemaining = Math.floor((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
              resolve({
                authorized,
                authorizationError: authError ? String(authError) : null,
                issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
                subject: cert.subject?.CN || finalHost,
                validTo: cert.valid_to,
                daysRemaining,
                isExpired: daysRemaining < 0,
                protocol
              });
            }
          );
          sock.on('error', (err) => resolve({ error: err.message }));
          sock.on('timeout', () => { sock.destroy(); resolve({ error: 'TLS handshake timeout' }); });
        });

        if (tlsInfo?.isExpired) {
          riskScore += 35;
          findings.push({
            severity: 'CRITICAL',
            category: 'SSL/TLS',
            title: 'Sertifikat SSL Sudah Kedaluwarsa (Expired)',
            detail: `Sertifikat berakhir pada ${tlsInfo.validTo}. Jangan kirim data sensitif ke situs ini.`
          });
        } else if (tlsInfo && tlsInfo.authorized === false && tlsInfo.authorizationError) {
          riskScore += 25;
          findings.push({
            severity: 'HIGH',
            category: 'SSL/TLS',
            title: `Sertifikat SSL Tidak Valid / Self-Signed (${tlsInfo.authorizationError})`,
            detail: 'Sertifikat tidak dipercaya oleh CA standar atau nama domain tidak cocok.'
          });
        } else if (tlsInfo?.daysRemaining !== undefined && tlsInfo.daysRemaining < 14) {
          riskScore += 10;
          findings.push({
            severity: 'LOW',
            category: 'SSL/TLS',
            title: `Sertifikat SSL Akan Kedaluwarsa dalam ${tlsInfo.daysRemaining} Hari`,
            detail: 'Pemilik situs perlu segera memperbarui sertifikat TLS.'
          });
        }
      } catch {}
    }

    // 4. HTTP Headers & HTML Content Analysis
    let httpInfo: any = null;
    let htmlAnalysis: any = null;

    if (finalResponse) {
      const headers = finalResponse.headers;
      const contentType = headers.get('content-type') || 'unknown';
      const serverHeader = headers.get('server') || 'Hidden';
      const cspHeader = headers.get('content-security-policy') || '';
      const hasHsts = Boolean(headers.get('strict-transport-security'));
      const hasCsp = Boolean(cspHeader);
      const hasXfo = Boolean(headers.get('x-frame-options'));
      const xctoVal = (headers.get('x-content-type-options') || '').toLowerCase();
      const hasXcto = xctoVal.includes('nosniff');

      const cspUnsafeInline = /'unsafe-inline'/i.test(cspHeader);
      const cspUnsafeEval = /'unsafe-eval'/i.test(cspHeader);
      const cspWildcard = /(?:script-src|default-src)[^;]*\*/i.test(cspHeader);

      httpInfo = {
        status: finalResponse.status,
        statusText: finalResponse.statusText,
        contentType,
        server: serverHeader,
        securityHeaders: { hasHsts, hasCsp, hasXfo, hasXcto },
        cspAudit: {
          present: hasCsp,
          unsafeInline: cspUnsafeInline,
          unsafeEval: cspUnsafeEval,
          wildcard: cspWildcard
        }
      };

      if (finalResponse.status >= 400) {
        findings.push({
          severity: 'INFO',
          category: 'HTTP Status',
          title: `Server Merespons Status Error HTTP ${finalResponse.status}`,
          detail: `Halaman mengembalikan status ${finalResponse.status} (${finalResponse.statusText || 'Error'}). Tautan mungkin rusak, kedaluwarsa, atau memblokir bot.`
        });
      }

      if (!hasHsts && finalParsed.protocol === 'https:') {
        riskScore += 5;
        findings.push({
          severity: 'LOW',
          category: 'Security Header',
          title: 'Header HSTS Tidak Aktif',
          detail: 'Strict-Transport-Security belum dipasang.'
        });
      }
      if (!hasCsp) {
        riskScore += 10;
        findings.push({
          severity: 'MEDIUM',
          category: 'XSS Defense (CSP)',
          title: 'Header Content-Security-Policy (CSP) Tidak Ditemukan',
          detail: 'Tanpa CSP, browser tidak memiliki lapisan mitigasi tambahan bila terjadi celah HTML Injection atau XSS di aplikasi.'
        });
      } else if (cspUnsafeInline || cspUnsafeEval || cspWildcard) {
        riskScore += 10;
        const weakFlags = [
          cspUnsafeInline ? "'unsafe-inline'" : null,
          cspUnsafeEval ? "'unsafe-eval'" : null,
          cspWildcard ? 'wildcard (*)' : null
        ].filter(Boolean).join(', ');
        findings.push({
          severity: 'MEDIUM',
          category: 'XSS Defense (CSP)',
          title: `Konfigurasi CSP Lemah (${weakFlags})`,
          detail: `Policy CSP mengizinkan ${weakFlags}, sehingga efektivitas pencegahan eksekusi skrip injeksi berkurang drastis.`
        });
      }
      if (!hasXcto) {
        riskScore += 5;
        findings.push({
          severity: 'LOW',
          category: 'MIME Sniffing / XSS',
          title: 'Header X-Content-Type-Options: nosniff Tidak Aktif',
          detail: 'Tanpa nosniff, browser berisiko menafsirkan file non-HTML sebagai HTML/JavaScript aktif (MIME confusion).'
        });
      }
      if (!hasCsp && !hasXfo) {
        riskScore += 5;
        findings.push({
          severity: 'LOW',
          category: 'Security Header',
          title: 'Proteksi Clickjacking (CSP frame-ancestors & X-Frame-Options) Lemah',
          detail: 'Situs tidak mengirim CSP maupun X-Frame-Options.'
        });
      }

      // Inspect HTML up to 250KB if text/html
      if (contentType.toLowerCase().includes('text/html') || contentType.toLowerCase().includes('application/xhtml')) {
        try {
          const rawText = await finalResponse.text();
          const html = rawText.slice(0, 250000);
          const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
          const pageTitle = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim().slice(0, 120) : '(Tanpa Title)';

          const hasPasswordField = /<input[^>]+type=["']?password["']?/i.test(html);
          const hasMetaRefresh = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=/i.test(html);
          const hiddenIframe = /<iframe[^>]+(display:\s*none|visibility:\s*hidden|width=["']?0["']?|height=["']?0["']?)/i.test(html);
          const obfuscatedJs = /eval\s*\(\s*atob\s*\(|document\.write\s*\(\s*unescape\s*\(/i.test(html);

          // Passive HTML Injection & DOM XSS surface inspection (no payload execution)
          const inlineEventHandlers = (html.match(/\son(?:error|load|click|mouseover|mouseenter|focus|blur|submit|input|change)\s*=\s*["']/gi) || []).length;
          const jsPseudoUriCount = (html.match(/(?:href|src|action)\s*=\s*["']\s*javascript:/gi) || []).length;
          const domSinkMatches: string[] = [];
          if (/\.innerHTML\s*=/i.test(html)) domSinkMatches.push('innerHTML');
          if (/\.outerHTML\s*=/i.test(html)) domSinkMatches.push('outerHTML');
          if (/document\.write(?:ln)?\s*\(/i.test(html)) domSinkMatches.push('document.write');
          if (/\.insertAdjacentHTML\s*\(/i.test(html)) domSinkMatches.push('insertAdjacentHTML');
          if (/\beval\s*\(/i.test(html)) domSinkMatches.push('eval()');
          if (/new\s+Function\s*\(/i.test(html)) domSinkMatches.push('new Function()');
          const unsandboxedIframes = (html.match(/<iframe(?![^>]*\bsandbox\b)[^>]*>/gi) || []).length;

          // Check external form action
          let externalFormAction: string | null = null;
          const formMatches = html.match(/<form[^>]+action=["']([^"']+)["']/gi) || [];
          for (const fm of formMatches) {
            const actMatch = fm.match(/action=["']([^"']+)["']/i);
            if (actMatch && /^https?:\/\//i.test(actMatch[1])) {
              try {
                const actHost = new URL(actMatch[1]).hostname.toLowerCase();
                if (actHost !== finalHost && !actHost.endsWith(`.${finalHost}`)) {
                  externalFormAction = actHost;
                  break;
                }
              } catch {}
            }
          }

          htmlAnalysis = {
            title: pageTitle,
            hasPasswordField,
            hasMetaRefresh,
            hiddenIframe,
            obfuscatedJs,
            externalFormAction,
            xssSurface: {
              inlineEventHandlers,
              jsPseudoUriCount,
              domSinks: domSinkMatches,
              unsandboxedIframes
            }
          };

          if (hasPasswordField && finalParsed.protocol === 'http:') {
            riskScore += 35;
            findings.push({
              severity: 'CRITICAL',
              category: 'Credential Risk',
              title: 'Form Password Berjalan di HTTP Tanpa Enkripsi!',
              detail: 'Halaman meminta input password melalui koneksi HTTP terbuka.'
            });
          }

          if (externalFormAction) {
            riskScore += 25;
            findings.push({
              severity: 'HIGH',
              category: 'Form Hijack / Phishing',
              title: `Form Mengirim Data ke Domain Eksternal (${externalFormAction})`,
              detail: `Form HTML pada ${finalHost} men-submit data ke domain berbeda '${externalFormAction}'.`
            });
          }

          if (hiddenIframe) {
            riskScore += 20;
            findings.push({
              severity: 'MEDIUM',
              category: 'Malicious HTML',
              title: 'Iframe Tersembunyi (0px / Hidden) Terdeteksi',
              detail: 'Ditemukan elemen iframe tersembunyi yang kerap dipakai untuk clickjacking atau drive-by tracking.'
            });
          }

          if (obfuscatedJs) {
            riskScore += 25;
            findings.push({
              severity: 'HIGH',
              category: 'Suspicious Script',
              title: 'Pola JavaScript Obfuscated (eval/atob) Terdeteksi',
              detail: 'Halaman mengeksekusi kode JS ter-encode base64 secara dinamis.'
            });
          }

          if (jsPseudoUriCount > 0) {
            riskScore += 15;
            findings.push({
              severity: 'MEDIUM',
              category: 'XSS Surface (HTML)',
              title: `Ditemukan ${jsPseudoUriCount} Tautan Skema 'javascript:' di HTML`,
              detail: 'Penggunaan URL javascript: di atribut href/src/action meningkatkan permukaan risiko injeksi HTML/XSS dan diblokir oleh CSP modern.'
            });
          }

          if (domSinkMatches.length > 0) {
            riskScore += 10;
            findings.push({
              severity: 'LOW',
              category: 'DOM XSS Sink Audit',
              title: `Terdeteksi DOM Sink Berisiko di Halaman (${domSinkMatches.join(', ')})`,
              detail: 'Jika input pengguna masuk ke sink DOM tersebut tanpa sanitasi (misal DOMPurify) atau textContent, aplikasi berisiko mengalami DOM-based HTML Injection / XSS.'
            });
          }

          if (inlineEventHandlers > 0 && (!hasCsp || cspUnsafeInline)) {
            riskScore += 5;
            findings.push({
              severity: 'INFO',
              category: 'HTML / CSP Hygiene',
              title: `Terdapat ${inlineEventHandlers} Inline Event Handler HTML Tanpa Strict CSP`,
              detail: 'Atribut event inline (onload/onclick/dll) menyulitkan penerapan CSP ketat berbasis nonce/hash.'
            });
          }

          if (unsandboxedIframes > 0) {
            findings.push({
              severity: 'INFO',
              category: 'HTML Hardening',
              title: `Ditemukan ${unsandboxedIframes} Elemen <iframe> Tanpa Atribut sandbox`,
              detail: 'Tambahkan atribut sandbox pada iframe pihak ketiga untuk membatasi akses skrip dan navigasi top-level.'
            });
          }

          if (hasMetaRefresh) {
            riskScore += 10;
            findings.push({
              severity: 'LOW',
              category: 'HTML Redirect',
              title: 'Meta Refresh Redirect Terdeteksi di HTML',
              detail: 'Halaman melakukan redirect tambahan melalui tag HTML <meta http-equiv="refresh">.'
            });
          }
        } catch {}
      }
    } else if (fetchError) {
      findings.push({
        severity: 'MEDIUM',
        category: 'Connectivity',
        title: `Gagal Mengambil Halaman (${fetchError})`,
        detail: 'Server target tidak merespons, menolak koneksi, atau memutus request sebelum selesai.'
      });
      riskScore += 15;
    }

    riskScore = Math.min(100, riskScore);
    let verdict = 'AMAN (SAFE)';
    if (riskScore >= 70) verdict = 'BERBAHAYA (CRITICAL RISK)';
    else if (riskScore >= 45) verdict = 'RISIKO TINGGI (HIGH RISK)';
    else if (riskScore >= 20) verdict = 'PERLU WASPADA (MEDIUM RISK)';
    else if (riskScore > 0) verdict = 'RISIKO RENDAH (LOW RISK)';

    if (riskScore >= 45) {
      recommendations.push('JANGAN masukkan password, OTP, PIN, atau data kartu di URL ini.');
      recommendations.push('Hindari mengunduh atau menjalankan file apa pun dari tautan tujuan.');
    } else if (riskScore >= 20) {
      recommendations.push('Verifikasi ulang domain akhir sebelum login atau mengirim informasi pribadi.');
    } else {
      recommendations.push('Tidak ditemukan indikator berbahaya utama, tetap pastikan domain tujuan sesuai yang dimaksud.');
    }

    if (finalParsed.protocol === 'http:') {
      recommendations.push('Aktifkan HTTPS (SSL/TLS) dan paksa redirect dari HTTP ke HTTPS.');
    }
    if (!httpInfo?.securityHeaders?.hasCsp || httpInfo?.cspAudit?.unsafeInline || httpInfo?.cspAudit?.unsafeEval) {
      recommendations.push("Terapkan Content-Security-Policy (CSP) ketat dengan nonce/hash tanpa 'unsafe-inline' atau 'unsafe-eval', serta gunakan contextual HTML encoding / DOMPurify untuk mencegah HTML Injection & XSS.");
    }

    res.json({
      success: true,
      inputUrl: normalizedInput,
      finalUrl: currentUrl,
      initialHost,
      finalHost,
      resolvedIps: finalIps,
      riskScore,
      verdict,
      redirectChain,
      tlsInfo,
      httpInfo,
      htmlAnalysis,
      findings,
      recommendations,
      timeMs: Date.now() - startTime
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Gagal memindai URL.' });
  }
});

// Wget / Direct File Downloader into Virtual Sandbox
app.post('/api/wget', async (req, res) => {
  const { url, filename } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  let targetUrl = url.trim();
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);

    const response = await fetch(targetUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Wget/1.21.3 (linux-gnu; ATRIX-VFS)'
      }
    });
    clearTimeout(timeout);

    if (!response.ok) {
      return res.status(response.status).json({
        error: `Server returned HTTP ${response.status} (${response.statusText})`
      });
    }

    // Determine filename
    let finalName = filename;
    if (!finalName) {
      const urlPath = new URL(targetUrl).pathname;
      const baseName = urlPath.split('/').filter(Boolean).pop();
      finalName = baseName || 'downloaded_file.txt';
    }

    const textContent = await response.text();
    const elapsed = Date.now() - startTime;

    res.json({
      success: true,
      filename: finalName,
      size: Buffer.byteLength(textContent, 'utf8'),
      content: textContent,
      contentType: response.headers.get('content-type') || 'text/plain',
      timeMs: elapsed
    });
  } catch (err: any) {
    res.status(500).json({ error: err.name === 'AbortError' ? 'Download timed out' : (err.message || 'Download failed') });
  }
});

// Defensive Security: Port Scanner (Checks standard or custom service ports with live TCP banner grabbing)
app.post('/api/security/portscan', async (req, res) => {
  const { host, customPorts, serviceVersion } = req.body;
  if (!host) return res.status(400).json({ error: 'Host is required' });

  const cleanHost = host.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].trim();

  // Resolve IP
  let resolvedIp = cleanHost;
  try {
    const dnsRes = await dns.lookup(cleanHost);
    resolvedIp = dnsRes.address;
  } catch {
    // Keep cleanHost
  }

  const serviceDictionary: Record<number, string> = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn', 143: 'IMAP',
    443: 'HTTPS', 445: 'microsoft-ds', 993: 'imaps', 995: 'pop3s', 1433: 'ms-sql-s',
    1521: 'oracle', 2049: 'nfs', 3306: 'MySQL', 3389: 'ms-wbt-server', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8000: 'http-alt', 8080: 'HTTP-Proxy', 8443: 'https-alt',
    9000: 'cslistener', 9200: 'Elasticsearch', 27017: 'MongoDB'
  };

  let targetPortList: { port: number; service: string }[] = [];

  if (Array.isArray(customPorts) && customPorts.length > 0) {
    const validPorts = customPorts
      .filter((p: any) => typeof p === 'number' && p >= 1 && p <= 65535)
      .slice(0, 64);
    targetPortList = validPorts.map((p: number) => ({
      port: p,
      service: serviceDictionary[p] || 'unknown'
    }));
  }

  if (targetPortList.length === 0) {
    targetPortList = [
      { port: 21, service: 'FTP' },
      { port: 22, service: 'SSH' },
      { port: 25, service: 'SMTP' },
      { port: 53, service: 'DNS' },
      { port: 80, service: 'HTTP' },
      { port: 110, service: 'POP3' },
      { port: 143, service: 'IMAP' },
      { port: 443, service: 'HTTPS' },
      { port: 3306, service: 'MySQL' },
      { port: 5432, service: 'PostgreSQL' },
      { port: 6379, service: 'Redis' },
      { port: 8080, service: 'HTTP-Alt' },
      { port: 8443, service: 'HTTPS-Alt' }
    ];
  }

  const startTime = Date.now();

  const checkPort = (portObj: { port: number; service: string }): Promise<{ port: number; service: string; status: 'open' | 'closed' | 'filtered'; timeMs: number; banner?: string }> => {
    return new Promise(resolve => {
      const t0 = performance.now();
      const socket = new net.Socket();
      socket.setTimeout(1400);

      let bannerData = '';

      socket.on('data', chunk => {
        bannerData += chunk.toString('utf8');
        if (bannerData.length > 256) bannerData = bannerData.substring(0, 256);
      });

      socket.on('connect', () => {
        const elapsed = Math.round(performance.now() - t0);

        // Attempt active banner probe if HTTP-like or text protocol
        if (serviceVersion) {
          if ([80, 8080, 8000, 3000].includes(portObj.port)) {
            try {
              socket.write(`HEAD / HTTP/1.0\r\nHost: ${cleanHost}\r\nUser-Agent: Nmap NSE\r\n\r\n`);
            } catch {}
          }
        }

        // Wait up to 350ms for banner or immediate close
        setTimeout(() => {
          let cleanBanner = bannerData.trim();
          if (cleanBanner) {
            const serverMatch = cleanBanner.match(/server:\s*([^\r\n]+)/i);
            if (serverMatch) cleanBanner = serverMatch[1].trim();
            else cleanBanner = cleanBanner.split('\n')[0].replace(/[\r\n]/g, '').trim();
          }
          socket.destroy();
          resolve({
            ...portObj,
            status: 'open',
            timeMs: elapsed,
            banner: cleanBanner || undefined
          });
        }, 350);
      });

      socket.on('timeout', () => {
        const elapsed = Math.round(performance.now() - t0);
        socket.destroy();
        resolve({ ...portObj, status: 'filtered', timeMs: elapsed });
      });

      socket.on('error', () => {
        const elapsed = Math.round(performance.now() - t0);
        resolve({ ...portObj, status: 'closed', timeMs: elapsed });
      });

      socket.connect(portObj.port, cleanHost);
    });
  };

  try {
    const results = await Promise.all(targetPortList.map(p => checkPort(p)));
    const totalElapsed = Date.now() - startTime;

    res.json({
      host: cleanHost,
      ip: resolvedIp,
      timeMs: totalElapsed,
      portsScanned: targetPortList.length,
      openPorts: results.filter(r => r.status === 'open'),
      results
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Port scan failed' });
  }
});

// Defensive Security: WHOIS Domain Information Lookup
app.post('/api/security/whois', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });

  const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase();

  try {
    const getWhois = (targetDomain: string, server = 'whois.iana.org'): Promise<string> => {
      return new Promise((resolve, reject) => {
        const socket = net.createConnection(43, server, () => {
          socket.write(targetDomain + '\r\n');
        });

        let data = '';
        socket.setTimeout(4000);
        socket.on('data', chunk => { data += chunk; });
        socket.on('end', () => resolve(data));
        socket.on('timeout', () => { socket.destroy(); reject(new Error('WHOIS connection timed out')); });
        socket.on('error', err => reject(err));
      });
    };

    let whoisData = await getWhois(cleanDomain);

    // If IANA gave a referral server (e.g. refer: whois.verisign-grs.com), query referral server
    const referMatch = whoisData.match(/refer:\s+([^\s]+)/i);
    if (referMatch && referMatch[1]) {
      try {
        const secondaryData = await getWhois(cleanDomain, referMatch[1]);
        if (secondaryData && secondaryData.length > 100) {
          whoisData = secondaryData;
        }
      } catch {
        // fallback to original whois data
      }
    }

    res.json({
      domain: cleanDomain,
      raw: whoisData
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'WHOIS query failed' });
  }
});

// Defensive Security: Subdomain Discovery (Passive Certificate Transparency via crt.sh + Active DNS)
app.post('/api/security/subdomains', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });

  const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase();
  const startTime = Date.now();
  const candidateSubs = new Set<string>();

  // 1. Common critical subdomain seeds
  const commonSubdomains = [
    'www', 'mail', 'api', 'dev', 'staging', 'admin', 'vpn', 'portal', 'auth',
    'login', 'secure', 'test', 'cdn', 'static', 'assets', 'blog', 'shop', 'app',
    'status', 'gateway', 'cloud', 'mx', 'ns1', 'ns2', 'm', 'dashboard', 'git',
    'beta', 'docs', 'remote', 'id', 'sso', 'member', 'panel'
  ];
  commonSubdomains.forEach(s => candidateSubs.add(`${s}.${cleanDomain}`));

  // 2. Query Certificate Transparency Logs (crt.sh)
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4500);
    const crtRes = await fetch(`https://crt.sh/?q=%.${cleanDomain}&output=json`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-Subdomain-Discovery/1.0' }
    });
    clearTimeout(timeout);
    if (crtRes.ok) {
      const crtData = await crtRes.json();
      if (Array.isArray(crtData)) {
        for (const entry of crtData.slice(0, 150)) {
          const names = String(entry.name_value || '').split('\n');
          for (let name of names) {
            name = name.trim().toLowerCase();
            if (name.startsWith('*.')) name = name.substring(2);
            if (name.endsWith(`.${cleanDomain}`) || name === cleanDomain) {
              candidateSubs.add(name);
            }
          }
        }
      }
    }
  } catch {
    // fallback to candidateSubs if crt.sh timeout/busy
  }

  // 3. Parallel Active DNS Resolution on the discovered candidates (test top 50)
  const candidateList = Array.from(candidateSubs).slice(0, 50);
  const discovered: { subdomain: string; ips: string[] }[] = [];

  await Promise.all(
    candidateList.map(async (fullSub) => {
      try {
        const ips = await dns.resolve4(fullSub);
        if (ips && ips.length > 0) {
          discovered.push({ subdomain: fullSub, ips });
        }
      } catch {
        // subdomain does not actively resolve to IPv4
      }
    })
  );

  const elapsed = Date.now() - startTime;

  res.json({
    domain: cleanDomain,
    scanned: candidateList.length,
    foundCount: discovered.length,
    subdomains: discovered,
    totalPassiveCandidates: candidateSubs.size,
    timeMs: elapsed
  });
});

// --- ATRIX INTELLIGENCE: Unified OSINT & Defensive Threat Intelligence Engine ---
const intelRateLimits = new Map<string, { count: number; resetTime: number }>();

app.post('/api/intel/scan', async (req, res) => {
  const forwarded = req.headers['x-forwarded-for'];
  const clientIp = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : req.socket.remoteAddress || '127.0.0.1';
  
  // Rate limiting: 40 requests per 60 seconds
  const now = Date.now();
  const rl = intelRateLimits.get(clientIp);
  if (rl && now < rl.resetTime) {
    if (rl.count >= 40) {
      return res.status(429).json({ error: 'Rate limit exceeded: Max 40 intelligence queries per minute.' });
    }
    rl.count++;
  } else {
    intelRateLimits.set(clientIp, { count: 1, resetTime: now + 60000 });
  }

  const { query, type = 'auto' } = req.body;
  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'A valid target query is required.' });
  }

  const rawTarget = query.trim().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim();
  if (!rawTarget || rawTarget.length > 256) {
    return res.status(400).json({ error: 'Target query format is invalid or exceeds 256 characters.' });
  }

  // Determine target type
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawTarget);
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(rawTarget);
  const isIpv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(rawTarget);
  const isIp = isIpv4 || isIpv6;

  let detectedType: 'ip' | 'domain' | 'email' = 'domain';
  if (type === 'email' || (type === 'auto' && isEmail)) {
    detectedType = 'email';
  } else if (type === 'ip' || (type === 'auto' && isIp)) {
    detectedType = 'ip';
  } else {
    detectedType = 'domain';
  }

  const startTime = Date.now();
  const sourcesAttributed: string[] = [];
  const vulnerabilities: { id: string; title: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'; desc: string }[] = [];
  const remediations: string[] = [];
  let threatScore = 0; // 0 = lowest risk / secure, 100 = critical risk

  try {
    let ipIntel: any = null;
    let domainIntel: any = null;
    let emailIntel: any = null;

    // Helper: IP metadata fetcher powered by multi-provider GeoIP + RIPE BGP engine
    const fetchIpInfo = async (ipAddr: string) => {
      const geo = await resolveDeepIpGeo(ipAddr);
      sourcesAttributed.push(
        geo.providersUsed.length > 0
          ? `Multi-Source GeoIP (${geo.providersUsed.join(', ')})`
          : 'Multi-Source GeoIP Engine'
      );
      if (geo.reverseDns.length > 0) {
        sourcesAttributed.push('Authoritative Reverse DNS (PTR)');
      }

      // Port probe on critical services
      const portsToProbe = [21, 22, 25, 80, 443, 3306, 5432, 6379, 8080];
      const openPorts: number[] = [];
      await Promise.all(portsToProbe.map(port => {
        return new Promise<void>(resolve => {
          const socket = new net.Socket();
          socket.setTimeout(900);
          socket.on('connect', () => {
            openPorts.push(port);
            socket.destroy();
            resolve();
          });
          socket.on('timeout', () => { socket.destroy(); resolve(); });
          socket.on('error', () => { resolve(); });
          socket.connect(port, ipAddr);
        });
      }));

      // Threat evaluation
      const dangerousPorts = openPorts.filter(p => [3306, 5432, 6379].includes(p));
      if (dangerousPorts.length > 0) {
        threatScore += 35;
        vulnerabilities.push({
          id: 'VULN-OPEN-DB',
          title: 'Exposed Database / Cache Port',
          severity: 'HIGH',
          desc: `Port database terbuka langsung ke publik (${dangerousPorts.join(', ')}). Risiko unauthorized access atau brute-force.`
        });
        remediations.push('Kunci port database (3306/5432/6379) menggunakan firewall (iptables/ufw/AWS SG) agar hanya bisa diakses via localhost atau internal VPN.');
      }

      if (geo.securityFlags.isProxy) {
        threatScore += 15;
        vulnerabilities.push({
          id: 'INTEL-PROXY-VPN',
          title: 'Proxy / VPN / Anonymizer Exit IP Terdeteksi',
          severity: 'LOW',
          desc: 'Alamat IP teridentifikasi sebagai node proxy, VPN, atau layanan anonimisasi oleh telemetry GeoIP.'
        });
      }

      if (geo.isBogon) {
        threatScore += 10;
        vulnerabilities.push({
          id: 'INFO-PRIVATE-IP',
          title: 'Private/Bogon IP Address',
          severity: 'INFO',
          desc: 'Alamat IP ini berada dalam alokasi RFC 1918 (jaringan lokal/private) dan tidak dapat dirutekan di internet publik.'
        });
      }

      return {
        ip: geo.ip,
        reverseDns: geo.reverseDns,
        continent: geo.continent,
        city: geo.city,
        region: geo.region,
        country: geo.country,
        countryCode: geo.country_code,
        postal: geo.postal,
        asn: geo.asn,
        isp: geo.isp,
        org: geo.org,
        bgpPrefix: geo.bgpPrefix,
        timezone: geo.timezone,
        coordinates: geo.coordinates,
        osmUrl: geo.osmUrl,
        networkType: geo.networkType,
        securityFlags: geo.securityFlags,
        consensus: geo.consensus,
        providersUsed: geo.providersUsed,
        openPorts,
        isHosting: geo.securityFlags.isHosting
      };
    };

    // 1. IP INTELLIGENCE FLOW
    if (detectedType === 'ip') {
      ipIntel = await fetchIpInfo(rawTarget);
    }

    // 2. DOMAIN INTELLIGENCE FLOW
    if (detectedType === 'domain') {
      sourcesAttributed.push('Public DNS Resolvers (A, AAAA, MX, TXT, NS)');
      const domainName = rawTarget.toLowerCase();

      // Parallel DNS queries
      const [aRecs, mxRecs, txtRecs, nsRecs] = await Promise.all([
        dns.resolve4(domainName).catch(() => [] as string[]),
        dns.resolveMx(domainName).catch(() => [] as any[]),
        dns.resolveTxt(domainName).catch(() => [] as string[][]),
        dns.resolveNs(domainName).catch(() => [] as string[])
      ]);

      // Check DMARC
      let dmarcRecs: string[][] = [];
      try {
        dmarcRecs = await dns.resolveTxt(`_dmarc.${domainName}`);
      } catch {}

      // Flat TXT strings
      const flatTxt = txtRecs.map(r => r.join(''));
      const flatDmarc = dmarcRecs.map(r => r.join(''));
      const hasSpf = flatTxt.some(t => t.toLowerCase().includes('v=spf1'));
      const hasDmarc = flatDmarc.some(t => t.toLowerCase().includes('v=dmarc1'));

      if (!hasSpf) {
        threatScore += 20;
        vulnerabilities.push({
          id: 'VULN-NO-SPF',
          title: 'Missing SPF Email Authentication',
          severity: 'MEDIUM',
          desc: 'Domain tidak memiliki TXT record SPF (Sender Policy Framework). Penyerang dapat memalsukan email (spoofing) mengatasnamakan domain ini.'
        });
        remediations.push('Tambahkan TXT record SPF (contoh: "v=spf1 include:_spf.google.com ~all") pada konfigurasi DNS.');
      }

      if (!hasDmarc) {
        threatScore += 25;
        vulnerabilities.push({
          id: 'VULN-NO-DMARC',
          title: 'Missing DMARC Policy',
          severity: 'HIGH',
          desc: 'Domain tidak memiliki policy DMARC (_dmarc.<domain>). Email phishing yang mencatut nama domain ini tidak akan ditolak oleh server penerima.'
        });
        remediations.push('Buat TXT record pada "_dmarc.' + domainName + '" dengan policy minimal p=quarantine atau p=reject.');
      }

      // Live SSL/TLS Inspection
      sourcesAttributed.push('Live TLS/SSL Certificate Inspection');
      let tlsInfo: any = null;
      try {
        await new Promise<void>((resolve) => {
          const socket = tls.connect({
            host: domainName,
            port: 443,
            servername: domainName,
            timeout: 3500
          }, () => {
            const cert = socket.getPeerCertificate(true);
            const protocol = socket.getProtocol();
            const cipher = socket.getCipher();
            socket.destroy();

            if (cert && cert.valid_to) {
              const validTo = new Date(cert.valid_to);
              const daysLeft = Math.round((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
              tlsInfo = {
                subject: cert.subject?.CN || domainName,
                issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown CA',
                validFrom: cert.valid_from,
                validTo: cert.valid_to,
                daysRemaining: daysLeft,
                isExpired: daysLeft <= 0,
                protocol,
                cipher: cipher?.name || 'Unknown'
              };

              if (daysLeft <= 7) {
                threatScore += 30;
                vulnerabilities.push({
                  id: 'VULN-SSL-EXPIRING',
                  title: 'SSL/TLS Certificate Expired or Expiring Soon',
                  severity: 'HIGH',
                  desc: `Sertifikat SSL akan kedaluwarsa dalam ${daysLeft} hari atau sudah habis. Browser akan menampilkan peringatan bahaya kepada pengunjung.`
                });
                remediations.push('Segera perbarui (renew) sertifikat SSL menggunakan Let\'s Encrypt certbot atau dashboard penyedia SSL.');
              }
            }
            resolve();
          });

          socket.on('error', () => { socket.destroy(); resolve(); });
          socket.on('timeout', () => { socket.destroy(); resolve(); });
        });
      } catch {}

      // HTTP Security Headers Inspection
      sourcesAttributed.push('HTTP Security Headers Audit');
      let headersAudit: any = null;
      try {
        const c = new AbortController();
        const t = setTimeout(() => c.abort(), 4000);
        const hRes = await fetch(`https://${domainName}`, {
          method: 'HEAD',
          signal: c.signal,
          headers: { 'User-Agent': 'ATRIX-OSINT-Engine/1.0' }
        });
        clearTimeout(t);
        const headers: Record<string, string> = {};
        hRes.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

        const hasHsts = !!headers['strict-transport-security'];
        const hasCsp = !!headers['content-security-policy'];
        const hasXfo = !!headers['x-frame-options'];

        if (!hasHsts) {
          threatScore += 15;
          vulnerabilities.push({
            id: 'VULN-NO-HSTS',
            title: 'Missing HSTS (Strict-Transport-Security)',
            severity: 'MEDIUM',
            desc: 'Website tidak memaksa browser selalu menggunakan HTTPS. Rentan terhadap serangan SSL Striping Man-in-the-Middle.'
          });
          remediations.push('Aktifkan header "Strict-Transport-Security: max-age=31536000; includeSubDomains".');
        }

        if (!hasCsp) {
          threatScore += 10;
          vulnerabilities.push({
            id: 'VULN-NO-CSP',
            title: 'Missing Content-Security-Policy (CSP)',
            severity: 'LOW',
            desc: 'Website tidak mendefinisikan pembatasan sumber script eksternal. Meningkatkan risiko serangan Cross-Site Scripting (XSS).'
          });
        }

        headersAudit = {
          server: headers['server'] || 'Undisclosed',
          hasHsts,
          hasCsp,
          hasXfo,
          hasXcto: headers['x-content-type-options'] === 'nosniff'
        };
      } catch {}

      // If A record exists, resolve IP info for domain's main server
      if (aRecs.length > 0) {
        ipIntel = await fetchIpInfo(aRecs[0]);
      }

      // Passive Certificate Transparency subdomains via crt.sh
      sourcesAttributed.push('Certificate Transparency Logs (crt.sh)');
      let subdomainsFound: string[] = [];
      try {
        const c = new AbortController();
        const t = setTimeout(() => c.abort(), 3500);
        const crtRes = await fetch(`https://crt.sh/?q=%.${domainName}&output=json`, { signal: c.signal });
        clearTimeout(t);
        if (crtRes.ok) {
          const crtData = await crtRes.json();
          if (Array.isArray(crtData)) {
            const subSet = new Set<string>();
            for (const item of crtData.slice(0, 30)) {
              const names = String(item.name_value || '').split('\n');
              for (const n of names) {
                const clean = n.trim().toLowerCase().replace(/^\*\./, '');
                if (clean.endsWith(domainName) && clean !== domainName) subSet.add(clean);
              }
            }
            subdomainsFound = Array.from(subSet).slice(0, 10);
          }
        }
      } catch {}

      domainIntel = {
        domain: domainName,
        ipAddresses: aRecs,
        mailServers: mxRecs.sort((a, b) => a.priority - b.priority),
        nameServers: nsRecs,
        txtRecordsCount: flatTxt.length,
        hasSpf,
        hasDmarc,
        tls: tlsInfo,
        headers: headersAudit,
        subdomains: subdomainsFound
      };
    }

    // 3. EMAIL EXPOSURE AWARENESS FLOW (Privacy-preserving, NO leaked passwords)
    if (detectedType === 'email') {
      sourcesAttributed.push('RFC 5322 Email Validator & DNS MX Verification');
      sourcesAttributed.push('Disposable Email Blacklist Repository');
      
      const emailDomain = rawTarget.split('@')[1].toLowerCase();
      const disposableList = ['tempmail.com', 'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'trashmail.com', 'yopmail.com', 'sharklasers.com', 'dispostable.com', 'getairmail.com'];
      const isDisposable = disposableList.includes(emailDomain);

      // Verify Mail Exchangers
      let mxRecs: any[] = [];
      try {
        mxRecs = await dns.resolveMx(emailDomain);
      } catch {}

      // Verify SPF and DMARC on domain
      let hasSpf = false;
      let hasDmarc = false;
      try {
        const txtRecs = await dns.resolveTxt(emailDomain);
        hasSpf = txtRecs.map(r => r.join('')).some(t => t.toLowerCase().includes('v=spf1'));
      } catch {}
      try {
        const dmarc = await dns.resolveTxt(`_dmarc.${emailDomain}`);
        hasDmarc = dmarc.map(r => r.join('')).some(t => t.toLowerCase().includes('v=dmarc1'));
      } catch {}

      if (isDisposable) {
        threatScore += 30;
        vulnerabilities.push({
          id: 'WARN-DISPOSABLE-EMAIL',
          title: 'Disposable / Throwaway Email Service',
          severity: 'MEDIUM',
          desc: 'Email ini menggunakan domain penyedia email sementara (disposable). Email ini tidak cocok untuk akun penting karena masa aktif sangat singkat.'
        });
      }

      if (mxRecs.length === 0) {
        threatScore += 40;
        vulnerabilities.push({
          id: 'VULN-DEAD-MX',
          title: 'No Valid Mail Exchanger (MX)',
          severity: 'HIGH',
          desc: `Domain "${emailDomain}" tidak memiliki Mail Exchanger (MX) aktif. Alamat email ini tidak dapat menerima pesan.`
        });
        remediations.push('Periksa kembali ejaan domain atau hubungi administrator untuk mengonfigurasi MX record.');
      }

      // Privacy-Preserving Exposure Guidance
      // NOTE: We NEVER display or retrieve plaintext passwords. We provide defensive awareness guidance.
      const exposureGuidance = [
        'Aktifkan Verifikasi Dua Langkah (2FA/MFA) menggunakan Authenticator App atau Hardware Security Key (FIDO2/YubiKey).',
        'Gunakan Password Manager untuk memastikan kata sandi unik pada setiap akun dan berpanjang minimal 16 karakter acak.',
        'Periksa riwayat sesi perangkat yang terhubung (Authorized Devices / OAuth Apps) dan cabut akses aplikasi yang tidak dikenal.'
      ];

      emailIntel = {
        email: rawTarget.toLowerCase(),
        domain: emailDomain,
        isValidSyntax: true,
        isDisposable,
        hasActiveMailServer: mxRecs.length > 0,
        mailServers: mxRecs.sort((a, b) => a.priority - b.priority),
        domainHasSpf: hasSpf,
        domainHasDmarc: hasDmarc,
        defensiveRecommendations: exposureGuidance,
        privacyNotice: 'Defensive Assurance: ATRIX tidak pernah menyimpan, mengekstrak, atau menampilkan kata sandi pengguna demi privasi etis.'
      };

      // Also get IP info of primary mail server if resolved
      if (mxRecs.length > 0 && mxRecs[0].exchange) {
        try {
          const mxIps = await dns.resolve4(mxRecs[0].exchange);
          if (mxIps.length > 0) {
            ipIntel = await fetchIpInfo(mxIps[0]);
          }
        } catch {}
      }
    }

    // Determine final Grade
    let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'A+';
    if (threatScore >= 65) grade = 'F';
    else if (threatScore >= 50) grade = 'D';
    else if (threatScore >= 35) grade = 'C';
    else if (threatScore >= 20) grade = 'B';
    else if (threatScore > 5) grade = 'A';

    const confidence: 'HIGH' | 'MEDIUM' | 'TENTATIVE' = sourcesAttributed.length >= 3 ? 'HIGH' : 'MEDIUM';

    res.json({
      success: true,
      query: rawTarget,
      detectedType,
      timestamp: new Date().toISOString(),
      threatScore: Math.min(100, threatScore),
      grade,
      confidence,
      sources: Array.from(new Set(sourcesAttributed)),
      ipIntel,
      domainIntel,
      emailIntel,
      vulnerabilities,
      remediations,
      timeMs: Date.now() - startTime
    });
  } catch (err: any) {
    res.status(500).json({
      error: err.message || 'Intelligence aggregation failed',
      timeMs: Date.now() - startTime
    });
  }
});

// Defensive Security: CVE Vulnerability Search (Official NIST NVD API)
app.post('/api/security/cve', async (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: 'CVE query or ID is required' });

  const cleanQuery = query.trim();
  const isCveId = /^CVE-\d{4}-\d{4,}$/i.test(cleanQuery);

  try {
    const targetUrl = isCveId
      ? `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cleanQuery.toUpperCase()}`
      : `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(cleanQuery)}&resultsPerPage=5`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const nvdRes = await fetch(targetUrl, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-CyberSecurity-Audit/1.0' }
    });
    clearTimeout(timeout);

    if (!nvdRes.ok) {
      return res.status(nvdRes.status).json({
        error: `NIST NVD service returned HTTP ${nvdRes.status}`
      });
    }

    const data = await nvdRes.json();
    const vulnerabilities = (data.vulnerabilities || []).slice(0, 5).map((item: any) => {
      const c = item.cve;
      const desc = c.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description';
      const metric = c.metrics?.cvssMetricV31?.[0] || c.metrics?.cvssMetricV30?.[0] || c.metrics?.cvssMetricV2?.[0];
      const cvssScore = metric?.cvssData?.baseScore || 'N/A';
      const severity = metric?.cvssData?.baseSeverity || metric?.baseSeverity || 'UNKNOWN';

      return {
        id: c.id,
        published: c.published,
        lastModified: c.lastModified,
        cvss: cvssScore,
        severity,
        description: desc
      };
    });

    res.json({
      query: cleanQuery,
      totalResults: data.totalResults || vulnerabilities.length,
      results: vulnerabilities
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'CVE search failed' });
  }
});

// 3. Real DNS Lookup
app.post('/api/dns', async (req, res) => {
  const { host, type = 'A' } = req.body;
  if (!host) {
    return res.status(400).json({ error: 'Host is required' });
  }

  // Clean host from protocol or path
  const cleanHost = host.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  try {
    const recordType = (type || 'A').toUpperCase();
    let records: any = [];

    switch (recordType) {
      case 'A':
        records = await dns.resolve4(cleanHost);
        break;
      case 'AAAA':
        records = await dns.resolve6(cleanHost);
        break;
      case 'MX':
        records = await dns.resolveMx(cleanHost);
        break;
      case 'TXT':
        records = await dns.resolveTxt(cleanHost);
        break;
      case 'NS':
        records = await dns.resolveNs(cleanHost);
        break;
      case 'CNAME':
        records = await dns.resolveCname(cleanHost);
        break;
      case 'SOA':
        records = await dns.resolveSoa(cleanHost);
        break;
      default:
        records = await dns.resolve4(cleanHost);
    }

    res.json({
      host: cleanHost,
      type: recordType,
      records
    });
  } catch (err: any) {
    res.status(400).json({
      host: cleanHost,
      type,
      error: err.code || err.message || 'DNS resolution failed'
    });
  }
});

// 4. Real Ping Latency Measurement
app.post('/api/ping', async (req, res) => {
  let { host } = req.body;
  if (!host) {
    return res.status(400).json({ error: 'Host is required' });
  }

  const cleanHost = host.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  // Check if user accidentally entered a WiFi SSID name without dot
  if (!cleanHost.includes('.') && cleanHost !== 'localhost') {
    return res.status(400).json({
      host: cleanHost,
      error: `Unknown host '${cleanHost}'. 'host' harus berupa nama domain (contoh: google.com) atau alamat IP (contoh: 8.8.8.8), bukan nama WiFi (SSID).`
    });
  }

  const samples: number[] = [];
  const count = 4;

  const measurePing = async (): Promise<number> => {
    const t0 = performance.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      await fetch(`https://${cleanHost}`, {
        method: 'HEAD',
        signal: controller.signal,
        cache: 'no-store'
      });
      clearTimeout(timeoutId);
      return Math.round(performance.now() - t0);
    } catch {
      try {
        const controller2 = new AbortController();
        const timeout2 = setTimeout(() => controller2.abort(), 2000);
        await fetch(`http://${cleanHost}`, {
          method: 'HEAD',
          signal: controller2.signal,
          cache: 'no-store'
        });
        clearTimeout(timeout2);
        return Math.round(performance.now() - t0);
      } catch {
        // Fallback to DNS resolution timing if web ports closed
        try {
          const tDns = performance.now();
          await dns.lookup(cleanHost);
          return Math.max(1, Math.round(performance.now() - tDns));
        } catch {
          return -1;
        }
      }
    }
  };

  for (let i = 0; i < count; i++) {
    const elapsed = await measurePing();
    samples.push(elapsed);
  }

  const successful = samples.filter(s => s >= 0);
  const min = successful.length ? Math.min(...successful) : 0;
  const max = successful.length ? Math.max(...successful) : 0;
  const avg = successful.length ? Math.round(successful.reduce((a, b) => a + b, 0) / successful.length) : 0;

  res.json({
    host: cleanHost,
    packetsSent: count,
    packetsReceived: successful.length,
    packetLoss: Math.round(((count - successful.length) / count) * 100),
    samples,
    min,
    max,
    avg
  });
});

// 5. Real Speed Test download endpoint
app.get('/api/speedtest/chunk', (req, res) => {
  const sizeMb = Math.min(Math.max(parseInt(req.query.mb as string) || 2, 1), 10);
  const buffer = Buffer.alloc(sizeMb * 1024 * 1024, 'X');
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', buffer.length.toString());
  res.setHeader('Cache-Control', 'no-store');
  res.send(buffer);
});

// 6. Weather ASCII forecast
app.get('/api/weather', async (req, res) => {
  const city = (req.query.city as string) || '';
  try {
    const target = city ? `https://wttr.in/${encodeURIComponent(city)}?AT` : 'https://wttr.in/?AT';
    const response = await fetch(target, {
      headers: {
        'User-Agent': 'curl/7.68.0'
      }
    });
    if (!response.ok) {
      throw new Error(`Weather service returned ${response.status}`);
    }
    const text = await response.text();
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(text);
  } catch (err: any) {
    res.status(500).send(`Unable to fetch weather: ${err.message}`);
  }
});

// 7. AI Shell Assistant (Gemini)
app.post('/api/ai', async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) {
    return res.status(400).json({ error: 'Prompt is required' });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return res.status(400).json({
      error: 'GEMINI_API_KEY is not configured in your environment secrets.'
    });
  }

  try {
    const ai = new GoogleGenAI();
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        systemInstruction: 'You are an intelligent CLI terminal companion inside ATRIX OS. Provide concise, expert, plaintext terminal-ready answers (code snippets, commands, short explanations, no excessive fluff). Use clean ASCII formatting.'
      }
    });

    res.json({
      reply: response.text || 'No response generated.'
    });
  } catch (err: any) {
    res.status(500).json({
      error: err.message || 'Failed to generate AI response'
    });
  }
});

// 8. RDNS (Reverse DNS PTR Lookup)
app.post('/api/security/rdns', async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP address is required' });
  try {
    const hostnames = await dns.reverse(ip.trim());
    res.json({ ip: ip.trim(), hostnames });
  } catch (err: any) {
    res.status(400).json({ error: err.code || err.message || 'Reverse DNS lookup failed' });
  }
});

// 9. Internet Archive Wayback Machine Availability
app.post('/api/security/wayback', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const target = `https://archive.org/wayback/available?url=${encodeURIComponent(url.trim())}`;
    const response = await fetch(target, { signal: controller.signal });
    clearTimeout(timeout);
    const data = await response.json();
    res.json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Wayback API query failed' });
  }
});

// 10. Wikipedia Entity & Person Profile (who / username)
app.post('/api/osint/who', async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name or query is required' });
  try {
    const cleanName = name.trim();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const target = `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(cleanName.replace(/\s+/g, '_'))}`;
    const response = await fetch(target, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-OSINT/1.0 (info@atrix.terminal)' }
    });
    clearTimeout(timeout);
    if (!response.ok) {
      return res.status(response.status).json({ error: `Wikipedia summary not found for "${cleanName}"` });
    }
    const data = await response.json();
    res.json({
      title: data.title,
      description: data.description || 'No subtitle description',
      extract: data.extract,
      pageUrl: data.content_urls?.desktop?.page || `https://en.wikipedia.org/wiki/${encodeURIComponent(cleanName)}`
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Wikipedia query failed' });
  }
});

// 11. GitHub Profile Intelligence (github <user>)
app.post('/api/osint/github', async (req, res) => {
  const { user } = req.body;
  if (!user) return res.status(400).json({ error: 'GitHub username is required' });
  try {
    const cleanUser = user.trim().replace(/^@/, '');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const response = await fetch(`https://api.github.com/users/${encodeURIComponent(cleanUser)}`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-Terminal-OSINT/1.0' }
    });
    clearTimeout(timeout);
    if (response.status === 404) {
      return res.status(404).json({ error: `User "${cleanUser}" not found on GitHub` });
    }
    const data = await response.json();
    res.json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'GitHub lookup failed' });
  }
});

// 12. GitHub User Public Repositories (ghrepos <user>)
app.post('/api/osint/ghrepos', async (req, res) => {
  const { user } = req.body;
  if (!user) return res.status(400).json({ error: 'GitHub username is required' });
  try {
    const cleanUser = user.trim().replace(/^@/, '');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const response = await fetch(`https://api.github.com/users/${encodeURIComponent(cleanUser)}/repos?sort=updated&per_page=10`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-Terminal-OSINT/1.0' }
    });
    clearTimeout(timeout);
    if (!response.ok) {
      return res.status(response.status).json({ error: `Failed to fetch repos for "${cleanUser}"` });
    }
    const data = await response.json();
    const repos = (data || []).map((r: any) => ({
      name: r.name,
      description: r.description || '(No description)',
      stars: r.stargazers_count,
      forks: r.forks_count,
      language: r.language || 'Plain',
      url: r.html_url,
      updated: r.updated_at
    }));
    res.json({ user: cleanUser, repos });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'GitHub repos lookup failed' });
  }
});

// 13. GitHub Leaked Commit Emails (ghemail <user>)
app.post('/api/osint/ghemail', async (req, res) => {
  const { user } = req.body;
  if (!user) return res.status(400).json({ error: 'GitHub username is required' });
  try {
    const cleanUser = user.trim().replace(/^@/, '');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const response = await fetch(`https://api.github.com/users/${encodeURIComponent(cleanUser)}/events/public`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-Terminal-OSINT/1.0' }
    });
    clearTimeout(timeout);
    if (!response.ok) {
      return res.status(response.status).json({ error: `Events not accessible for "${cleanUser}"` });
    }
    const events = await response.json();
    const emailsFound = new Set<string>();
    if (Array.isArray(events)) {
      for (const ev of events) {
        if (ev.type === 'PushEvent' && ev.payload?.commits) {
          for (const c of ev.payload.commits) {
            if (c.author?.email && !c.author.email.includes('users.noreply.github.com')) {
              emailsFound.add(`${c.author.name} <${c.author.email}>`);
            }
          }
        }
      }
    }
    res.json({
      user: cleanUser,
      found: Array.from(emailsFound)
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'GitHub commit email scan failed' });
  }
});

// 14. Email Validation & MX Check (email <address>)
app.post('/api/osint/email', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email address is required' });
  const cleanEmail = email.trim().toLowerCase();
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const isValidFormat = regex.test(cleanEmail);
  if (!isValidFormat) {
    return res.json({ email: cleanEmail, valid: false, reason: 'Invalid email syntax' });
  }
  const domain = cleanEmail.split('@')[1];
  const disposableDomains = ['tempmail.com', 'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'trashmail.com', 'yopmail.com', 'sharklasers.com', 'dispostable.com'];
  const isDisposable = disposableDomains.includes(domain);
  let mxRecords: any[] = [];
  try {
    mxRecords = await dns.resolveMx(domain);
  } catch {
    // no mx
  }
  res.json({
    email: cleanEmail,
    domain,
    valid: isValidFormat && mxRecords.length > 0,
    hasMx: mxRecords.length > 0,
    isDisposable,
    mxRecords: mxRecords.sort((a, b) => a.priority - b.priority)
  });
});

// 15. OpenStreetMap Geocoding (geo <place>)
app.post('/api/osint/geo', async (req, res) => {
  const { place } = req.body;
  if (!place) return res.status(400).json({ error: 'Place name is required' });
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const target = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(place.trim())}&format=json&limit=5`;
    const response = await fetch(target, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-OSINT-Terminal/1.0' }
    });
    clearTimeout(timeout);
    if (!response.ok) throw new Error(`OSM Nominatim returned HTTP ${response.status}`);
    const data = await response.json();
    res.json({ query: place.trim(), results: data });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Geocoding failed' });
  }
});

// 16. OpenStreetMap Reverse Geocoding (revgeo <lat> <lon>)
app.post('/api/osint/revgeo', async (req, res) => {
  const { lat, lon } = req.body;
  if (lat === undefined || lon === undefined) return res.status(400).json({ error: 'Latitude and Longitude are required' });
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const target = `https://nominatim.openstreetmap.org/reverse?lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lon)}&format=json`;
    const response = await fetch(target, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-OSINT-Terminal/1.0' }
    });
    clearTimeout(timeout);
    if (!response.ok) throw new Error(`OSM Nominatim returned HTTP ${response.status}`);
    const data = await response.json();
    res.json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Reverse geocoding failed' });
  }
});

// 17. Country Facts Lookup (country <name>)
app.post('/api/osint/country', async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Country name is required' });
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const target = `https://restcountries.com/v3.1/name/${encodeURIComponent(name.trim())}?fullText=false`;
    const response = await fetch(target, { signal: controller.signal });
    clearTimeout(timeout);
    if (!response.ok) return res.status(404).json({ error: `Country "${name}" not found` });
    const data = await response.json();
    const c = data[0];
    res.json({
      name: c.name?.common,
      officialName: c.name?.official,
      capital: c.capital?.[0] || 'N/A',
      region: c.region,
      subregion: c.subregion,
      population: c.population ? c.population.toLocaleString() : 'N/A',
      flag: c.flag || '',
      currencies: c.currencies ? Object.values(c.currencies).map((curr: any) => `${curr.name} (${curr.symbol || ''})`).join(', ') : 'N/A',
      languages: c.languages ? Object.values(c.languages).join(', ') : 'N/A',
      timezones: c.timezones?.join(', ') || 'N/A',
      borders: c.borders?.join(', ') || 'None'
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Country lookup failed' });
  }
});

// 18. Sherlock Username Presence Reconnaissance across 16 major platforms (sherlock <user> / stalk <user>)
app.post('/api/osint/sherlock', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  const u = username.trim().replace(/^@/, '');
  const startTime = Date.now();

  const platforms = [
    {
      name: 'GitHub',
      category: 'Developer',
      url: `https://github.com/${u}`,
      check: async () => {
        const r = await fetch(`https://api.github.com/users/${encodeURIComponent(u)}`, {
          headers: { 'User-Agent': 'ATRIX-OSINT/1.0' }
        });
        if (r.status === 200) {
          const d = await r.json();
          return { exists: true, extra: `${d.public_repos} repos, ${d.followers} followers` };
        }
        return { exists: false };
      }
    },
    {
      name: 'Reddit',
      category: 'Social',
      url: `https://www.reddit.com/user/${u}`,
      check: async () => {
        const r = await fetch(`https://www.reddit.com/user/${encodeURIComponent(u)}/about.json`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ATRIX-Recon/1.0' }
        });
        if (r.status === 200) {
          const d = await r.json();
          if (d?.data?.name) {
            return { exists: true, extra: `Karma: ${d.data.total_karma || 0}` };
          }
        }
        return { exists: false };
      }
    },
    {
      name: 'Docker Hub',
      category: 'Developer',
      url: `https://hub.docker.com/u/${u}`,
      check: async () => {
        const r = await fetch(`https://hub.docker.com/v2/users/${encodeURIComponent(u)}`, {
          headers: { 'User-Agent': 'ATRIX-OSINT/1.0' }
        });
        return { exists: r.status === 200 };
      }
    },
    {
      name: 'Dev.to',
      category: 'Blogging',
      url: `https://dev.to/${u}`,
      check: async () => {
        const r = await fetch(`https://dev.to/api/users/by_username?url=${encodeURIComponent(u)}`, {
          headers: { 'User-Agent': 'ATRIX-OSINT/1.0' }
        });
        if (r.status === 200) {
          const d = await r.json();
          return { exists: !!d.username, extra: d.summary || '' };
        }
        return { exists: false };
      }
    },
    {
      name: 'HackerNews',
      category: 'Tech Community',
      url: `https://news.ycombinator.com/user?id=${u}`,
      check: async () => {
        const r = await fetch(`https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(u)}.json`);
        if (r.status === 200) {
          const d = await r.json();
          return { exists: d !== null && d.id === u, extra: d ? `Karma: ${d.karma}` : '' };
        }
        return { exists: false };
      }
    },
    {
      name: 'GitLab',
      category: 'Developer',
      url: `https://gitlab.com/${u}`,
      check: async () => {
        const r = await fetch(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(u)}`, {
          headers: { 'User-Agent': 'ATRIX-OSINT/1.0' }
        });
        if (r.status === 200) {
          const d = await r.json();
          return { exists: Array.isArray(d) && d.length > 0 };
        }
        return { exists: false };
      }
    },
    {
      name: 'npm',
      category: 'Package Manager',
      url: `https://www.npmjs.com/~${u}`,
      check: async () => {
        const r = await fetch(`https://www.npmjs.com/~${encodeURIComponent(u)}`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });
        return { exists: r.status === 200 };
      }
    },
    {
      name: 'PyPI',
      category: 'Package Manager',
      url: `https://pypi.org/user/${u}/`,
      check: async () => {
        const r = await fetch(`https://pypi.org/user/${encodeURIComponent(u)}/`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });
        return { exists: r.status === 200 };
      }
    },
    {
      name: 'Medium',
      category: 'Blogging',
      url: `https://medium.com/@${u}`,
      check: async () => {
        const r = await fetch(`https://medium.com/@${encodeURIComponent(u)}`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });
        return { exists: r.status === 200 };
      }
    },
    {
      name: 'Chess.com',
      category: 'Gaming',
      url: `https://www.chess.com/member/${u}`,
      check: async () => {
        const r = await fetch(`https://api.chess.com/pub/player/${encodeURIComponent(u.toLowerCase())}`, {
          headers: { 'User-Agent': 'ATRIX-OSINT/1.0' }
        });
        if (r.status === 200) {
          const d = await r.json();
          return { exists: true, extra: `Title: ${d.title || 'Player'}, Status: ${d.status}` };
        }
        return { exists: false };
      }
    },
    {
      name: 'Codeforces',
      category: 'Competitive Coding',
      url: `https://codeforces.com/profile/${u}`,
      check: async () => {
        const r = await fetch(`https://codeforces.com/api/user.info?handles=${encodeURIComponent(u)}`);
        if (r.status === 200) {
          const d = await r.json();
          if (d.status === 'OK' && d.result?.length) {
            const user = d.result[0];
            return { exists: true, extra: `Rank: ${user.rank || 'unranked'}, Rating: ${user.rating || 0}` };
          }
        }
        return { exists: false };
      }
    },
    {
      name: 'Gravatar',
      category: 'Avatar & Identity',
      url: `https://en.gravatar.com/${u}`,
      check: async () => {
        const r = await fetch(`https://en.gravatar.com/${encodeURIComponent(u)}.json`, {
          headers: { 'User-Agent': 'ATRIX-OSINT/1.0' }
        });
        return { exists: r.status === 200 };
      }
    },
    {
      name: 'Telegram',
      category: 'Messenger',
      url: `https://t.me/${u}`,
      check: async () => {
        const r = await fetch(`https://t.me/${encodeURIComponent(u)}`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });
        if (r.status === 200) {
          const html = await r.text();
          const hasUser = html.includes('tgme_page_title') || html.includes('tgme_page_extra');
          const isInvalid = html.includes('If you have Telegram, you can contact') && !html.includes('tgme_page_description');
          return { exists: hasUser && !isInvalid };
        }
        return { exists: false };
      }
    },
    {
      name: 'Pastebin',
      category: 'Data Storage',
      url: `https://pastebin.com/u/${u}`,
      check: async () => {
        const r = await fetch(`https://pastebin.com/u/${encodeURIComponent(u)}`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });
        return { exists: r.status === 200 };
      }
    },
    {
      name: 'Pinterest',
      category: 'Social Media',
      url: `https://www.pinterest.com/${u}/`,
      check: async () => {
        const r = await fetch(`https://www.pinterest.com/${encodeURIComponent(u)}/`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });
        return { exists: r.status === 200 };
      }
    },
    {
      name: 'Keybase',
      category: 'Cryptography / Crypto ID',
      url: `https://keybase.io/${u}`,
      check: async () => {
        const r = await fetch(`https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(u)}`);
        if (r.status === 200) {
          const d = await r.json();
          return { exists: d.status?.code === 0 && d.them?.length > 0 && d.them[0] !== null };
        }
        return { exists: false };
      }
    }
  ];

  const results = await Promise.all(
    platforms.map(async (p) => {
      try {
        const timeoutPromise = new Promise<{ exists: boolean; extra?: string }>((resolve) =>
          setTimeout(() => resolve({ exists: false }), 2800)
        );
        const res = await Promise.race([p.check(), timeoutPromise]);
        return {
          name: p.name,
          category: p.category,
          url: p.url,
          exists: res.exists,
          extra: (res as any).extra || undefined
        };
      } catch {
        return {
          name: p.name,
          category: p.category,
          url: p.url,
          exists: false
        };
      }
    })
  );

  const foundProfiles = results.filter(r => r.exists);
  const elapsed = Date.now() - startTime;

  res.json({
    username: u,
    totalScanned: platforms.length,
    foundCount: foundProfiles.length,
    elapsedMs: elapsed,
    results
  });
});

// 19. Web Tech Stack & CMS Profiler (techstack <domain> / webtech <domain>)
app.post('/api/security/techstack', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL or domain is required' });

  let cleanTarget = target.trim();
  if (!cleanTarget.startsWith('http://') && !cleanTarget.startsWith('https://')) {
    cleanTarget = 'https://' + cleanTarget;
  }

  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const response = await fetch(cleanTarget, {
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (ATRIX-TechProfiler/1.0)'
      }
    });
    clearTimeout(timeout);

    const html = await response.text();
    const headers: Record<string, string> = {};
    response.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });

    const detected: { category: string; name: string; evidence: string; confidence: 'High' | 'Medium' }[] = [];

    // --- Web Server & CDN / WAF ---
    if (headers['server']) {
      detected.push({ category: 'Web Server', name: headers['server'], evidence: `Header Server: ${headers['server']}`, confidence: 'High' });
    }
    if (headers['cf-ray'] || headers['cf-cache-status']) {
      detected.push({ category: 'CDN / WAF', name: 'Cloudflare', evidence: `Header CF-RAY: ${headers['cf-ray'] || 'detected'}`, confidence: 'High' });
    }
    if (headers['x-amz-cf-id']) {
      detected.push({ category: 'CDN', name: 'AWS CloudFront', evidence: 'Header X-Amz-Cf-Id', confidence: 'High' });
    }
    if (headers['x-varnish'] || headers['via']?.includes('varnish')) {
      detected.push({ category: 'Reverse Proxy / Cache', name: 'Varnish Cache', evidence: 'Varnish header detected', confidence: 'High' });
    }
    if (headers['x-powered-by']) {
      detected.push({ category: 'Platform / Runtime', name: headers['x-powered-by'], evidence: `Header X-Powered-By: ${headers['x-powered-by']}`, confidence: 'High' });
    }
    if (headers['x-vercel-id']) {
      detected.push({ category: 'Hosting Platform', name: 'Vercel Edge', evidence: 'Header X-Vercel-Id', confidence: 'High' });
    }

    // --- CMS & Site Builders ---
    if (html.includes('/wp-content/') || html.includes('/wp-includes/') || html.includes('wp-json')) {
      detected.push({ category: 'CMS', name: 'WordPress', evidence: 'WordPress path assets found in HTML', confidence: 'High' });
    }
    if (html.includes('cdn.shopify.com') || html.includes('Shopify.theme')) {
      detected.push({ category: 'E-Commerce / CMS', name: 'Shopify', evidence: 'Shopify theme engine & CDN scripts', confidence: 'High' });
    }
    if (html.includes('data-wf-page') || html.includes('webflow.js')) {
      detected.push({ category: 'Site Builder', name: 'Webflow', evidence: 'Webflow dataset attributes', confidence: 'High' });
    }
    if (html.includes('ghost-root') || html.includes('content/images/size/')) {
      detected.push({ category: 'CMS / Publication', name: 'Ghost', evidence: 'Ghost publication markers', confidence: 'High' });
    }
    if (html.includes('Drupal.settings') || headers['x-drupal-cache']) {
      detected.push({ category: 'CMS', name: 'Drupal', evidence: 'Drupal settings or cache headers', confidence: 'High' });
    }

    // --- Frontend Frameworks & Libraries ---
    if (html.includes('__NEXT_DATA__') || html.includes('/_next/static/')) {
      detected.push({ category: 'JavaScript Framework', name: 'Next.js (React)', evidence: '__NEXT_DATA__ hydration block', confidence: 'High' });
    } else if (html.includes('react') || html.includes('data-reactroot') || html.includes('_reactListening')) {
      detected.push({ category: 'JavaScript Library', name: 'React', evidence: 'React DOM hydration attributes', confidence: 'High' });
    }
    if (html.includes('__NUXT__') || html.includes('/_nuxt/')) {
      detected.push({ category: 'JavaScript Framework', name: 'Nuxt.js (Vue)', evidence: '__NUXT__ state payload', confidence: 'High' });
    } else if (html.includes('data-v-') || html.includes('vue.global')) {
      detected.push({ category: 'JavaScript Framework', name: 'Vue.js', evidence: 'Vue scoped CSS attributes', confidence: 'High' });
    }
    if (html.includes('ng-version') || html.includes('ng-app')) {
      detected.push({ category: 'JavaScript Framework', name: 'Angular', evidence: 'Angular ng-version attribute', confidence: 'High' });
    }
    if (html.includes('svelte') || html.includes('class="svelte-')) {
      detected.push({ category: 'UI Compiler', name: 'Svelte', evidence: 'Svelte class hashes', confidence: 'High' });
    }
    if (html.includes('tailwindcss') || /class="[^"]*(flex|grid|items-center|justify-between|text-|bg-)[^"]*"/.test(html)) {
      detected.push({ category: 'CSS Framework', name: 'Tailwind CSS', evidence: 'Utility classes & Tailwind signature', confidence: 'Medium' });
    }
    if (html.includes('bootstrap') || html.includes('btn-primary')) {
      detected.push({ category: 'CSS Framework', name: 'Bootstrap', evidence: 'Bootstrap class definitions', confidence: 'Medium' });
    }
    if (html.includes('jquery.min.js') || html.includes('jQuery')) {
      detected.push({ category: 'JavaScript Utility', name: 'jQuery', evidence: 'jQuery script tag reference', confidence: 'High' });
    }

    // --- Analytics & Trackers ---
    if (html.includes('googletagmanager.com') || html.includes('gtag(')) {
      detected.push({ category: 'Analytics / Tracking', name: 'Google Tag Manager / GA4', evidence: 'gtag or GTM script embed', confidence: 'High' });
    }
    if (html.includes('connect.facebook.net') || html.includes('fbq(')) {
      detected.push({ category: 'Analytics / Tracking', name: 'Meta Pixel', evidence: 'Facebook Pixel script embed', confidence: 'High' });
    }
    if (html.includes('hotjar.com') || html.includes('_hjSettings')) {
      detected.push({ category: 'Heatmap / Analytics', name: 'Hotjar', evidence: 'Hotjar tracking configuration', confidence: 'High' });
    }

    // Remove duplicates
    const unique = detected.filter((v, i, a) => a.findIndex(t => t.name.toLowerCase() === v.name.toLowerCase()) === i);

    res.json({
      targetUrl: cleanTarget,
      finalUrl: response.url,
      httpStatus: response.status,
      elapsedMs: Date.now() - startTime,
      technologiesCount: unique.length,
      technologies: unique
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Tech stack audit failed' });
  }
});

// 20. Email Security & Anti-Spoofing Audit (emailsec <domain> / dmarc <domain>)
app.post('/api/security/emailsec', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });

  const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase();
  const startTime = Date.now();

  try {
    // 1. Check MX records
    let mxRecords: any[] = [];
    try {
      mxRecords = await dns.resolveMx(cleanDomain);
    } catch {
      // no mx
    }

    // 2. Check SPF in TXT records
    let spfRecord: string | null = null;
    try {
      const txtRecords = await dns.resolveTxt(cleanDomain);
      const flattened = txtRecords.map(r => r.join(''));
      const found = flattened.find(t => t.startsWith('v=spf1'));
      if (found) spfRecord = found;
    } catch {
      // no txt
    }

    // 3. Check DMARC in TXT records on _dmarc.<domain>
    let dmarcRecord: string | null = null;
    try {
      const dmarcTxt = await dns.resolveTxt(`_dmarc.${cleanDomain}`);
      const flattened = dmarcTxt.map(r => r.join(''));
      const found = flattened.find(t => t.startsWith('v=DMARC1'));
      if (found) dmarcRecord = found;
    } catch {
      // no dmarc
    }

    // 4. Check common DKIM selectors
    const dkimSelectors = ['google', 'default', 'k1', 'mail', 's1', 'selector1'];
    let dkimFound: { selector: string; record: string } | null = null;

    for (const sel of dkimSelectors) {
      try {
        const dkimTxt = await dns.resolveTxt(`${sel}._domainkey.${cleanDomain}`);
        const flattened = dkimTxt.map(r => r.join(''));
        const found = flattened.find(t => t.includes('v=DKIM1') || t.includes('p='));
        if (found) {
          dkimFound = { selector: sel, record: found };
          break;
        }
      } catch {
        // try next
      }
    }

    // Evaluation & Spoofing Risk
    let spoofingRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
    const issues: string[] = [];

    if (mxRecords.length === 0) {
      issues.push('Domain has no active MX mail records.');
    }

    if (!spfRecord) {
      issues.push('Missing SPF record: Anyone can send forged emails pretending to be this domain.');
      spoofingRisk = 'CRITICAL';
    } else {
      if (spfRecord.includes('+all') || spfRecord.includes('?all')) {
        issues.push('SPF ends with +all or ?all (neutral/permissive): Invalid sender validation.');
        spoofingRisk = 'HIGH';
      } else if (spfRecord.includes('~all')) {
        issues.push('SPF ends with ~all (SoftFail): Spoofed mail may still land in Inboxes.');
      }
    }

    if (!dmarcRecord) {
      issues.push('Missing DMARC policy (_dmarc): Mail servers cannot enforce rejection of spoofed emails.');
      if (spoofingRisk === 'LOW') spoofingRisk = 'HIGH';
    } else {
      const policyMatch = dmarcRecord.match(/p=([a-zA-Z]+)/);
      const policy = policyMatch ? policyMatch[1].toLowerCase() : 'none';
      if (policy === 'none') {
        issues.push('DMARC policy is set to "p=none" (monitoring only): Spoofed emails are NOT rejected.');
        if (spoofingRisk === 'LOW') spoofingRisk = 'MEDIUM';
      }
    }

    res.json({
      domain: cleanDomain,
      elapsedMs: Date.now() - startTime,
      spoofingRisk,
      mxCount: mxRecords.length,
      mxRecords: mxRecords.sort((a, b) => a.priority - b.priority),
      spf: {
        present: !!spfRecord,
        raw: spfRecord,
        policy: spfRecord ? (spfRecord.includes('-all') ? 'Strict HardFail (-all)' : spfRecord.includes('~all') ? 'SoftFail (~all)' : 'Permissive') : 'None'
      },
      dmarc: {
        present: !!dmarcRecord,
        raw: dmarcRecord,
        policy: dmarcRecord ? (dmarcRecord.match(/p=([a-zA-Z]+)/)?.[1] || 'unknown') : 'None'
      },
      dkim: {
        verifiedSelector: dkimFound ? dkimFound.selector : null,
        record: dkimFound ? dkimFound.record : null
      },
      issues
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Email security audit failed' });
  }
});

// 21. Crawler Intelligence: Robots.txt & Security.txt Extractor (robots <domain> / securitytxt <domain>)
app.post('/api/security/crawlers', async (req, res) => {
  const { domain, type = 'all' } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });

  const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase();

  try {
    const fetchWithTimeout = async (url: string) => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      try {
        const resp = await fetch(url, {
          signal: controller.signal,
          headers: { 'User-Agent': 'ATRIX-CrawlerIntel/1.0' }
        });
        clearTimeout(timeout);
        if (!resp.ok) return null;
        return await resp.text();
      } catch {
        return null;
      }
    };

    const [robotsTxt, securityTxt] = await Promise.all([
      fetchWithTimeout(`https://${cleanDomain}/robots.txt`),
      fetchWithTimeout(`https://${cleanDomain}/.well-known/security.txt`).then(async res => {
        if (res) return res;
        return await fetchWithTimeout(`https://${cleanDomain}/security.txt`);
      })
    ]);

    // Parse disallow lines from robots
    const disallows: string[] = [];
    const sitemaps: string[] = [];
    if (robotsTxt) {
      robotsTxt.split('\n').forEach(line => {
        const trimmed = line.trim();
        if (/^disallow:\s*/i.test(trimmed)) {
          const pathVal = trimmed.replace(/^disallow:\s*/i, '').trim();
          if (pathVal) disallows.push(pathVal);
        } else if (/^sitemap:\s*/i.test(trimmed)) {
          sitemaps.push(trimmed.replace(/^sitemap:\s*/i, '').trim());
        }
      });
    }

    // Parse security.txt fields (RFC 9116)
    const securityFields: Record<string, string[]> = {};
    if (securityTxt) {
      securityTxt.split('\n').forEach(line => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          const colonIdx = trimmed.indexOf(':');
          if (colonIdx > 0) {
            const field = trimmed.substring(0, colonIdx).trim().toLowerCase();
            const val = trimmed.substring(colonIdx + 1).trim();
            if (!securityFields[field]) securityFields[field] = [];
            securityFields[field].push(val);
          }
        }
      });
    }

    res.json({
      domain: cleanDomain,
      robots: {
        found: !!robotsTxt,
        disallows: disallows.slice(0, 30),
        totalDisallows: disallows.length,
        sitemaps: sitemaps.slice(0, 5),
        rawExcerpt: robotsTxt ? robotsTxt.split('\n').slice(0, 35).join('\n') : null
      },
      securityTxt: {
        found: !!securityTxt,
        fields: securityFields,
        rawExcerpt: securityTxt ? securityTxt.split('\n').slice(0, 30).join('\n') : null
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Crawler intelligence scan failed' });
  }
});

// 22. CORS Policy & HTTP Methods Probe (cors <url> / httpmethods <url>)
app.post('/api/security/cors', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  let targetUrl = url.trim();
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const evilOrigin = 'https://evil-attacker-exploit.com';
  const startTime = Date.now();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    // 1. Test CORS Origin Reflection with preflight OPTIONS
    const optRes = await fetch(targetUrl, {
      method: 'OPTIONS',
      signal: controller.signal,
      headers: {
        'Origin': evilOrigin,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'X-Requested-With, Authorization',
        'User-Agent': 'ATRIX-SecurityAudit/1.0'
      }
    });

    const getRes = await fetch(targetUrl, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'Origin': evilOrigin,
        'User-Agent': 'ATRIX-SecurityAudit/1.0'
      }
    });
    clearTimeout(timeout);

    const acaoOpt = optRes.headers.get('access-control-allow-origin') || '';
    const acacOpt = optRes.headers.get('access-control-allow-credentials') || '';
    const acamOpt = optRes.headers.get('access-control-allow-methods') || '';
    const allowHeader = optRes.headers.get('allow') || '';

    const acaoGet = getRes.headers.get('access-control-allow-origin') || '';
    const acacGet = getRes.headers.get('access-control-allow-credentials') || '';

    const allowedOrigin = acaoGet || acaoOpt || 'None';
    const allowsCredentials = acacGet.toLowerCase() === 'true' || acacOpt.toLowerCase() === 'true';

    let vulnerability = 'SECURE (Origin rejected or no CORS header)';
    let severity: 'CRITICAL' | 'HIGH' | 'LOW' | 'NONE' = 'NONE';

    if (allowedOrigin === evilOrigin && allowsCredentials) {
      vulnerability = 'CRITICAL: Arbitrary Origin Reflection WITH Credentials Allowed! (Authenticated session hijacking)';
      severity = 'CRITICAL';
    } else if (allowedOrigin === '*') {
      vulnerability = 'OPEN CORS: Access-Control-Allow-Origin: * (Public read access)';
      severity = 'LOW';
    } else if (allowedOrigin === evilOrigin) {
      vulnerability = 'ARBITRARY ORIGIN REFLECTION (Cross-origin reading allowed without credentials)';
      severity = 'HIGH';
    } else if (allowedOrigin === 'null' && allowsCredentials) {
      vulnerability = 'HIGH: Null Origin Trusted with Credentials';
      severity = 'HIGH';
    }

    res.json({
      targetUrl,
      elapsedMs: Date.now() - startTime,
      cors: {
        allowOrigin: allowedOrigin,
        allowCredentials: allowsCredentials,
        allowMethods: acamOpt || allowHeader || 'GET, HEAD, POST',
        vulnerability,
        severity
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'CORS audit probe failed' });
  }
});

// 23. Gravatar Identity OSINT (gravatar <email>)
app.post('/api/osint/gravatar', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    const cleanEmail = email.trim().toLowerCase();
    const hash = crypto.createHash('md5').update(cleanEmail).digest('hex');

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(`https://en.gravatar.com/${hash}.json`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ATRIX-OSINT/1.0' }
    });
    clearTimeout(timeout);

    if (resp.status === 404) {
      return res.status(404).json({
        email: cleanEmail,
        hash,
        found: false,
        avatarUrl: `https://www.gravatar.com/avatar/${hash}?d=identicon`,
        message: 'No public Gravatar profile registered for this email address.'
      });
    }

    if (!resp.ok) {
      throw new Error(`Gravatar returned HTTP ${resp.status}`);
    }

    const data = await resp.json();
    const entry = data.entry?.[0] || {};

    const accounts = (entry.accounts || []).map((a: any) => ({
      domain: a.domain,
      display: a.display,
      url: a.url,
      verified: a.verified === 'true'
    }));

    res.json({
      email: cleanEmail,
      hash,
      found: true,
      displayName: entry.displayName || entry.preferredUsername || 'N/A',
      profileUrl: entry.profileUrl || `https://gravatar.com/${hash}`,
      aboutMe: entry.aboutMe || 'N/A',
      currentLocation: entry.currentLocation || 'N/A',
      avatarUrl: entry.thumbnailUrl || `https://www.gravatar.com/avatar/${hash}`,
      verifiedAccounts: accounts
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Gravatar OSINT lookup failed' });
  }
});

// 24. Bug Bounty: Subdomain Takeover & Dangling DNS Audit (subtakeover <domain>)
app.post('/api/bounty/takeover', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });

  const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase();
  const startTime = Date.now();

  const PROVIDERS = [
    { name: 'GitHub Pages', cname: 'github.io', fingerprint: "There isn't a GitHub Pages site here" },
    { name: 'AWS S3 Bucket', cname: 'amazonaws.com', fingerprint: 'NoSuchBucket' },
    { name: 'Heroku', cname: 'herokuapp.com', fingerprint: 'No such app' },
    { name: 'Shopify', cname: 'myshopify.com', fingerprint: 'Sorry, this shop is currently unavailable' },
    { name: 'Zendesk', cname: 'zendesk.com', fingerprint: 'Help Center Closed' },
    { name: 'Fastly CDN', cname: 'fastly.net', fingerprint: 'Fastly error: unknown domain' },
    { name: 'Ghost', cname: 'ghost.io', fingerprint: 'The thing you were looking for is no longer here' },
    { name: 'Surge.sh', cname: 'surge.sh', fingerprint: 'project not found' },
    { name: 'Bitbucket', cname: 'bitbucket.io', fingerprint: 'Repository not found' },
    { name: 'ReadMe.io', cname: 'readme.io', fingerprint: 'Project doesnt exist' },
    { name: 'Azure Web App', cname: 'azurewebsites.net', fingerprint: 'Web App not found' }
  ];

  try {
    let candidates: string[] = [];
    const parts = cleanDomain.split('.');
    if (parts.length > 2) {
      candidates.push(cleanDomain);
    } else {
      const commonPrefixes = ['blog', 'dev', 'app', 'help', 'support', 'shop', 'status', 'docs', 'cdn', 'api', 'test', 'staging', 'mail', 'portal'];
      candidates = commonPrefixes.map(p => `${p}.${cleanDomain}`);
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);
      const crtRes = await fetch(`https://crt.sh/?q=%25.${cleanDomain}&output=json`, { signal: controller.signal });
      clearTimeout(timeout);
      if (crtRes.ok) {
        const certs = await crtRes.json();
        const found = new Set<string>();
        for (const item of certs.slice(0, 25)) {
          const names = String(item.name_value).split('\n');
          for (const n of names) {
            const clean = n.trim().toLowerCase().replace(/^\*\./, '');
            if (clean.endsWith(`.${cleanDomain}`) && clean !== cleanDomain && !clean.includes('*')) {
              found.add(clean);
            }
          }
        }
        candidates = Array.from(new Set([...candidates, ...Array.from(found).slice(0, 10)]));
      }
    } catch {
      // crt.sh fallback
    }

    candidates = candidates.slice(0, 15);

    const auditResults = await Promise.all(
      candidates.map(async sub => {
        let cnameRecords: string[] = [];
        try {
          cnameRecords = await dns.resolveCname(sub);
        } catch {
          // No CNAME
        }

        if (cnameRecords.length === 0) {
          return {
            subdomain: sub,
            hasCname: false,
            cname: null,
            provider: null,
            status: 'SAFE',
            vulnerable: false,
            details: 'No CNAME record'
          };
        }

        const cnameTarget = cnameRecords[0].toLowerCase();
        const matchedProvider = PROVIDERS.find(p => cnameTarget.includes(p.cname));

        if (!matchedProvider) {
          return {
            subdomain: sub,
            hasCname: true,
            cname: cnameTarget,
            provider: 'External Service',
            status: 'ROUTED / SAFE',
            vulnerable: false,
            details: `CNAME points to ${cnameTarget}`
          };
        }

        let isDangling = false;
        let responseCode = 0;

        try {
          const ctrl = new AbortController();
          const tId = setTimeout(() => ctrl.abort(), 3000);
          const probe = await fetch(`http://${sub}`, {
            signal: ctrl.signal,
            headers: { 'User-Agent': 'ATRIX-TakeoverAudit/1.0' }
          });
          clearTimeout(tId);
          responseCode = probe.status;
          const body = await probe.text();
          if (body.includes(matchedProvider.fingerprint)) {
            isDangling = true;
          }
        } catch {
          isDangling = false;
        }

        return {
          subdomain: sub,
          hasCname: true,
          cname: cnameTarget,
          provider: matchedProvider.name,
          status: isDangling ? 'CRITICAL: VULNERABLE' : 'PROTECTED',
          vulnerable: isDangling,
          httpStatus: responseCode || null,
          details: isDangling
            ? `Dangling DNS detected! ${matchedProvider.name} fingerprint returned. Takeover risk present.`
            : `Active service on ${matchedProvider.name} (${cnameTarget})`
        };
      })
    );

    const vulnerableItems = auditResults.filter(r => r.vulnerable);

    res.json({
      domain: cleanDomain,
      elapsedMs: Date.now() - startTime,
      scannedCount: auditResults.length,
      vulnerableCount: vulnerableItems.length,
      isVulnerable: vulnerableItems.length > 0,
      results: auditResults
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Takeover audit failed' });
  }
});

// 25. Bug Bounty: Scope & Program Intelligence (bounty <domain>)
app.post('/api/bounty/program', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });

  const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase();
  const brandName = cleanDomain.split('.')[0];
  const startTime = Date.now();

  try {
    let h1Found = false;
    const h1Url = `https://hackerone.com/${brandName}`;
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 2500);
      const h1Res = await fetch(h1Url, { method: 'HEAD', signal: ctrl.signal });
      clearTimeout(t);
      if (h1Res.status === 200 || h1Res.status === 301 || h1Res.status === 302) {
        h1Found = true;
      }
    } catch {
      //
    }

    let bcFound = false;
    const bcUrl = `https://bugcrowd.com/${brandName}`;
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 2500);
      const bcRes = await fetch(bcUrl, { method: 'HEAD', signal: ctrl.signal });
      clearTimeout(t);
      if (bcRes.status === 200 || bcRes.status === 301 || bcRes.status === 302) {
        bcFound = true;
      }
    } catch {
      //
    }

    let securityTxtFound = false;
    const contacts: string[] = [];
    let policyUrl = '';

    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 2500);
      const secRes = await fetch(`https://${cleanDomain}/.well-known/security.txt`, { signal: ctrl.signal });
      clearTimeout(t);
      if (secRes.ok) {
        securityTxtFound = true;
        const text = await secRes.text();
        text.split('\n').forEach(line => {
          const l = line.trim();
          if (/^contact:\s*/i.test(l)) contacts.push(l.replace(/^contact:\s*/i, ''));
          if (/^policy:\s*/i.test(l)) policyUrl = l.replace(/^policy:\s*/i, '');
        });
      }
    } catch {
      //
    }

    res.json({
      domain: cleanDomain,
      brandName,
      elapsedMs: Date.now() - startTime,
      programs: {
        hackerone: { found: h1Found, url: h1Found ? h1Url : null },
        bugcrowd: { found: bcFound, url: bcFound ? bcUrl : null },
        securityTxt: {
          found: securityTxtFound,
          contacts,
          policyUrl: policyUrl || null,
          url: `https://${cleanDomain}/.well-known/security.txt`
        }
      },
      hasVdpOrBounty: h1Found || bcFound || securityTxtFound,
      scopeEstimate: {
        inScope: [`*.${cleanDomain}`, `api.${cleanDomain}`, `app.${cleanDomain}`, `www.${cleanDomain}`],
        outOfScope: ['Third-party services without explicit written consent', 'Physical attacks & Social Engineering', 'Volumetric DDoS attacks']
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Bug bounty intelligence probe failed' });
  }
});

// 26. Website Purpose & Intelligence Analyzer (info <url>)
app.post('/api/web/info', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL atau domain target diperlukan.' });

  let rawTarget = String(url).trim();
  rawTarget = rawTarget.replace(/^["']|["']$/g, '');

  let targetUrl = rawTarget;
  if (!/^https?:\/\//i.test(targetUrl)) {
    targetUrl = 'https://' + targetUrl;
  }

  const startTime = Date.now();
  let fetchResp: Response | null = null;
  let finalUrl = targetUrl;
  let html = '';
  let status = 0;
  let statusText = '';
  let serverHeader = '';
  let contentType = '';
  let usedProtocol = targetUrl.startsWith('https') ? 'HTTPS' : 'HTTP';

  const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (ATRIX-WebIntel/1.0)';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    try {
      fetchResp = await fetch(targetUrl, {
        method: 'GET',
        headers: {
          'User-Agent': userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'
        },
        signal: controller.signal,
        redirect: 'follow'
      });
    } catch (httpsErr: any) {
      if (targetUrl.startsWith('https://')) {
        const fallbackHttp = targetUrl.replace(/^https:\/\//i, 'http://');
        usedProtocol = 'HTTP';
        fetchResp = await fetch(fallbackHttp, {
          method: 'GET',
          headers: {
            'User-Agent': userAgent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
          },
          signal: controller.signal,
          redirect: 'follow'
        });
      } else {
        throw httpsErr;
      }
    }
    clearTimeout(timeout);

    if (fetchResp) {
      status = fetchResp.status;
      statusText = fetchResp.statusText;
      finalUrl = fetchResp.url || targetUrl;
      serverHeader = fetchResp.headers.get('server') || 'Cloudflare / Hidden';
      contentType = fetchResp.headers.get('content-type') || 'text/html';
      html = await fetchResp.text();
    }
  } catch (err: any) {
    return res.status(502).json({
      error: `Gagal mengakses website '${rawTarget}': ${err.message || 'Connection failed'}. Pastikan website aktif.`
    });
  }

  const elapsedMs = Date.now() - startTime;

  const decodeHtml = (str: string) => {
    return str
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&apos;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&nbsp;/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  };

  // Extract metadata via regex
  const getTag = (pattern: RegExp) => {
    const match = html.match(pattern);
    return match ? decodeHtml(match[1]) : '';
  };

  const title = getTag(/<title[^>]*>([^<]+)<\/title>/i) || 'Tidak ada title';
  const metaDesc = getTag(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i) ||
                   getTag(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i);
  const ogTitle = getTag(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']*)["']/i);
  const ogDesc = getTag(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']*)["']/i);
  const ogSiteName = getTag(/<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']*)["']/i);
  const ogType = getTag(/<meta[^>]+property=["']og:type["'][^>]+content=["']([^"']*)["']/i);
  const ogImage = getTag(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']*)["']/i);
  const keywords = getTag(/<meta[^>]+name=["']keywords["'][^>]+content=["']([^"']*)["']/i);
  const generator = getTag(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']*)["']/i);

  // Extract headings
  const h1Matches: string[] = [];
  const h1Regex = /<h1[^>]*>([^<]+)<\/h1>/gi;
  let m1;
  while ((m1 = h1Regex.exec(html)) !== null && h1Matches.length < 5) {
    const text = decodeHtml(m1[1].replace(/<[^>]*>/g, ''));
    if (text) h1Matches.push(text);
  }

  const h2Matches: string[] = [];
  const h2Regex = /<h2[^>]*>([^<]+)<\/h2>/gi;
  let m2;
  while ((m2 = h2Regex.exec(html)) !== null && h2Matches.length < 5) {
    const text = decodeHtml(m2[1].replace(/<[^>]*>/g, ''));
    if (text) h2Matches.push(text);
  }

  // Extract clean visible text snippet
  const bodyText = html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
    .replace(/<svg\b[^<]*(?:(?!<\/svg>)<[^<]*)*<\/svg>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();

  const textSnippet = bodyText.substring(0, 3000);

  // Comprehensive, human-friendly website analysis
  let whatIsIt = '';
  let functions: string[] = [];
  let forWhat: string[] = [];
  let whatCanYouDo: string[] = [];
  let category = 'Portal Informasi & Web Publik';
  let targetAudience = 'Masyarakat umum dan pengguna internet';
  let entityOrBrand = ogSiteName || title.split(/[-–|]/)[0].trim() || 'Pemilik Web';
  let safetyAssessment = `Situs aktif dan merespons normal dengan protokol ${finalUrl.startsWith('https') ? 'HTTPS terenkripsi SSL/TLS [Aman]' : 'HTTP standar (belum terenkripsi SSL)'}.`;
  let analysisEngine = 'ATRIX Semantic Intelligence';

  // Try Gemini AI synthesis if GEMINI_API_KEY is available
  if (process.env.GEMINI_API_KEY) {
    try {
      const ai = new GoogleGenAI({});
      const prompt = `Anda adalah analis website dan konsultan cyber intelligence di terminal ATRIX OS.
Tugas Anda adalah menjelaskan website target dengan BAHASA INDONESIA YANG SANGAT MUDAH DIMENGERTI ORANG AWAM, TIDAK KAKU, DAN DETAIL:
"Website ini sebenarnya apa, fungsi utamanya apa, dan untuk apa orang mengunjunginya?".

Data website:
- Target URL: ${targetUrl} (Final: ${finalUrl})
- Title: ${title}
- Meta Description: ${metaDesc || 'N/A'}
- OpenGraph Info: SiteName="${ogSiteName || 'N/A'}", Title="${ogTitle || 'N/A'}", Desc="${ogDesc || 'N/A'}"
- Headings: ${[...h1Matches, ...h2Matches].slice(0, 6).join(' | ') || 'N/A'}
- Cuplikan Konten: ${textSnippet.substring(0, 1600)}

Format respon HANYA JSON MURNI tanpa markdown wrap:
{
  "whatIsIt": "Penjelasan gamblang dan jelas dalam 2 kalimat santai: Website ini sebenarnya apa (misal: apakah toko online, web portofolio pribadi, pemutar musik, portal berita, dll) dan milik siapa",
  "functions": [
    "Fungsi utama 1: Buat apa web ini dibuat",
    "Fungsi utama 2: Layanan apa yang disediakan",
    "Fungsi utama 3: Media apa yang ditawarkan"
  ],
  "forWhat": [
    "Alasan pengunjung 1: Untuk apa orang mengunjunginya (manfaat pengunjung A)",
    "Alasan pengunjung 2: Manfaat pengunjung B"
  ],
  "whatCanYouDo": [
    "Hal yang bisa dilakukan di web ini 1",
    "Hal yang bisa dilakukan di web ini 2",
    "Hal yang bisa dilakukan di web ini 3"
  ],
  "category": "Nama kategori yang gampang dipahami (misal: Portofolio Pribadi & CV Digital, Toko Online & Belanja, Streaming Musik & Hiburan, dll)",
  "targetAudience": "Siapa saja orang yang ditargetkan mengunjungi web ini",
  "entityOrBrand": "Nama brand, pemilik, atau organisasi",
  "safetyAssessment": "Penilaian singkat keamanan & reputasi situs"
}`;

      const aiPromise = ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt
      });
      const timeoutPromise = new Promise<never>((_, reject) => setTimeout(() => reject(new Error('AI timeout')), 4500));
      const aiResponse = await Promise.race([aiPromise, timeoutPromise]);

      const rawAiText = aiResponse.text?.trim() || '';
      const cleanJson = rawAiText.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
      const parsed = JSON.parse(cleanJson);

      if (parsed.whatIsIt) whatIsIt = parsed.whatIsIt;
      if (Array.isArray(parsed.functions) && parsed.functions.length > 0) functions = parsed.functions;
      if (Array.isArray(parsed.forWhat) && parsed.forWhat.length > 0) forWhat = parsed.forWhat;
      if (Array.isArray(parsed.whatCanYouDo) && parsed.whatCanYouDo.length > 0) whatCanYouDo = parsed.whatCanYouDo;
      if (parsed.category) category = parsed.category;
      if (parsed.targetAudience) targetAudience = parsed.targetAudience;
      if (parsed.entityOrBrand) entityOrBrand = parsed.entityOrBrand;
      if (parsed.safetyAssessment) safetyAssessment = parsed.safetyAssessment;
      analysisEngine = 'Gemini 3.8 Flash AI Engine';
    } catch {
      // fallback to rich heuristic classifier
    }
  }

  // Rich Heuristic Fallback
  if (!whatIsIt || functions.length === 0) {
    const combined = `${targetUrl} ${finalUrl} ${title} ${metaDesc} ${ogDesc} ${h1Matches.join(' ')} ${h2Matches.join(' ')} ${textSnippet}`.toLowerCase();
    const domainHost = new URL(finalUrl).hostname.toLowerCase();

    // 1. Portofolio Pribadi / CV Online / Developer Showcase
    const isPortfolio =
      combined.includes('portofolio') ||
      combined.includes('portfolio') ||
      combined.includes('cv online') ||
      combined.includes('curriculum vitae') ||
      combined.includes('resume') ||
      (combined.includes('developer') && (combined.includes('fullstack') || combined.includes('frontend') || combined.includes('backend') || combined.includes('personal') || combined.includes('proyek') || combined.includes('koleksi')));

    if (isPortfolio) {
      const ownerName = title.split(/[-–|]/)[0].trim() || ogSiteName || 'seorang Fullstack Developer';
      whatIsIt = `Website ini adalah Website Portofolio Pribadi (CV Digital & Showroom Karya Online) milik ${ownerName}. Website ini dibuat sebagai etalase digital untuk memperkenalkan keahlian dan memamerkan proyek-proyek aplikasi yang pernah dibuat.`;
      functions = [
        `Memamerkan bukti hasil karya nyata (koleksi proyek website dan aplikasi) yang pernah dikembangkan oleh ${ownerName}.`,
        `Menjelaskan penguasaan keahlian teknis (seperti React, TypeScript, Tailwind CSS, hingga sistem backend server).`,
        `Menyediakan jalur kontak langsung bagi calon klien atau perusahaan yang ingin menyewa jasanya atau menawarkan kerja sama proyek (freelance).`
      ];
      forWhat = [
        `Calon Klien / Pemesan Jasa: Ingin melihat kualitas hasil karya dan bukti kemampuan sebelum memutuskan menyewa jasanya.`,
        `Perusahaan & HRD / Perekrut Kerja: Mengecek portofolio, riwayat pengalaman, dan skill teknis untuk kebutuhan rekrutmen kerja.`,
        `Sesama Rekan Programmer: Melihat referensi desain web modern, animasi interaktif, atau menjalin koneksi profesional.`
      ];
      whatCanYouDo = [
        `Melihat galeri showcase proyek lengkap dengan demo tampilan dan teknologi yang dipakai`,
        `Membaca profil latar belakang, riwayat karier, dan daftar keahlian teknis pemilik`,
        `Menghubungi pemilik melalui tombol kontak, email, atau tautan sosial media resmi`
      ];
      category = 'Portofolio Pribadi & Jasa Pembuatan Website/Aplikasi (CV Digital)';
      targetAudience = 'Calon klien yang mau bikin web, HRD/Perekrut kerja, dan komunitas developer';
    }
    // 2. Toko Online / E-Commerce / Marketplace
    else if (
      combined.includes('toko online') ||
      combined.includes('toko') ||
      combined.includes('shop') ||
      combined.includes('store') ||
      combined.includes('keranjang') ||
      combined.includes('cart') ||
      combined.includes('checkout') ||
      combined.includes('beli sekarang') ||
      combined.includes('katalog produk') ||
      combined.includes('belanja online') ||
      domainHost.includes('tokopedia') ||
      domainHost.includes('shopee')
    ) {
      whatIsIt = `Website ini adalah Toko Online (E-Commerce) tempat pengunjung bisa menjelajahi katalog barang dagangan, melihat harga, dan melakukan transaksi jual-beli secara digital.`;
      functions = [
        `Menyajikan etalase produk lengkap dengan foto barang, spesifikasi, dan daftar harga resmi.`,
        `Menyediakan sistem keranjang belanja (cart) dan checkout pembayaran online (transfer bank/QRIS/e-wallet).`,
        `Mengelola transaksi pemesanan dan pengiriman barang ke alamat pembeli.`
      ];
      forWhat = [
        `Pembeli / Konsumen: Mencari, memilih, dan membeli produk kebutuhan secara praktis tanpa harus datang ke toko fisik.`,
        `Pencari Diskon: Membandingkan harga produk dan memanfaatkan kupon promo atau potongan ongkos kirim.`
      ];
      whatCanYouDo = [
        `Mencari dan memfilter barang berdasarkan kategori produk atau rentang harga`,
        `Memasukkan barang ke keranjang belanja dan menyelesaikan pembayaran secara online`,
        `Melacak status pengiriman paket pesanan hingga sampai di rumah`
      ];
      category = 'Toko Online & Belanja Digital (E-Commerce)';
      targetAudience = 'Masyarakat umum, pembeli daring, dan konsumen kebutuhan belanja';
    }
    // 3. Streaming Musik & Audio
    else if (
      combined.includes('streaming musik') ||
      combined.includes('music streaming') ||
      combined.includes('synced lyrics') ||
      combined.includes('playlist') ||
      combined.includes('lagu') ||
      combined.includes('lirik') ||
      domainHost.includes('quzetify') ||
      domainHost.includes('spotify')
    ) {
      whatIsIt = `Website ini adalah Aplikasi Pemutar Musik Online (Streaming Audio) di mana pengunjung dapat mendengarkan berbagai lagu dan menikmati konten audio langsung dari browser tanpa perlu mengunduh file manual.`;
      functions = [
        `Memutar trek audio/lagu secara instan dengan kontrol pemutar musik interaktif (play, pause, next).`,
        `Menampilkan lirik lagu yang bergulir otomatis (synced lyrics) mengikuti tempo alunan musik.`,
        `Menyajikan daftar putar lagu baru, album terpopuler, dan fitur pencarian lagu favorit.`
      ];
      forWhat = [
        `Penikmat Musik: Mendengarkan lagu favorit saat sedang santai, belajar, bekerja, atau berolahraga.`,
        `Penggemar Karaoke: Membaca lirik lagu yang berjalan sinkron untuk ikut bernyanyi bersama.`
      ];
      whatCanYouDo = [
        `Memilih, memutar, dan mengganti lagu favorit langsung dari browser`,
        `Melihat lirik lagu yang sinkron otomatis saat lagu sedang berputar`,
        `Menjelajahi daftar rilisan lagu baru dan rekomendasi album musik`
      ];
      category = 'Aplikasi Streaming Musik & Hiburan Audio Online';
      targetAudience = 'Penikmat musik, pelajar, pekerja, dan masyarakat yang mencari hiburan';
    }
    // 4. Developer Platform / Git Code Repository
    else if (
      domainHost.includes('github') ||
      domainHost.includes('gitlab') ||
      combined.includes('developer platform') ||
      combined.includes('source code') ||
      combined.includes('git repository') ||
      combined.includes('version control')
    ) {
      whatIsIt = `Website ini adalah Platform Pengembang & Penyimpanan Kode Software (Git Code Hosting) tempat jutaan programmer dan perusahaan di seluruh dunia menyimpan, berbagi, dan berkolaborasi membuat aplikasi.`;
      functions = [
        `Menyimpan seluruh riwayat perubahan kode program (version control Git) secara aman di cloud server.`,
        `Memudahkan kerja sama tim programmer dari berbagai penjuru dunia dalam satu proyek bersama.`,
        `Menyediakan sistem pelacak kendala (issues), automasi build/test (CI/CD), dan distribusi software open-source.`
      ];
      forWhat = [
        `Programmer & Tim IT: Mengembangkan aplikasi bersama dan mengamankan backup kode program di cloud.`,
        `Pelajar & Komunitas: Mendownload library siap pakai atau mempelajari cara kerja software open-source.`
      ];
      whatCanYouDo = [
        `Menjelajahi repository kode program dan file proyek aplikasi`,
        `Melihat dokumentasi cara instalasi software, rilis versi, dan kontribusi pembuatnya`,
        `Melaporkan bug atau mengirimkan usulan perbaikan kode program (pull request)`
      ];
      category = 'Platform Pengembang & Kolaborasi Kode Software (Git)';
      targetAudience = 'Software engineer, tim IT perusahaan, mahasiswa teknologi, dan komunitas open-source';
    }
    // 5. Portal Berita & Media Informasi
    else if (
      combined.includes('berita') ||
      combined.includes('news') ||
      combined.includes('kabar terkini') ||
      combined.includes('headline') ||
      combined.includes('liputan') ||
      domainHost.includes('detik') ||
      domainHost.includes('kompas')
    ) {
      whatIsIt = `Website ini adalah Portal Berita & Media Informasi yang menerbitkan artikel kabar harian, liputan peristiwa terkini, dan informasi aktual untuk masyarakat.`;
      functions = [
        `Menyampaikan berita terbaru dari berbagai rubrik (politik, ekonomi, olahraga, teknologi, hiburan).`,
        `Memberikan liputan langsung dan penjelasan atas isu penting yang sedang hangat dibicarakan publik.`,
        `Menyediakan arsip bacaan dan liputan investigasi yang dapat diakses umum.`
      ];
      forWhat = [
        `Pembaca Berita: Memperbarui wawasan tentang peristiwa hangat hari ini di Indonesia maupun dunia.`,
        `Masyarakat: Mengetahui kabar pengumuman resmi, perkiraan cuaca, atau perkembangan kebijakan terkini.`
      ];
      whatCanYouDo = [
        `Membaca artikel berita terkini yang terus diperbarui secara berkala`,
        `Mencari topik kabar spesifik berdasarkan kategori rubrik`,
        `Membagikan artikel informasi ke media sosial atau aplikasi perpesanan`
      ];
      category = 'Portal Berita & Media Massa Digital';
      targetAudience = 'Masyarakat umum, pembaca berita, profesional, dan pemerhati isu publik';
    }
    // 6. Layanan Finansial & Perbankan (Bank / Fintech)
    else if (
      combined.includes('bank') ||
      combined.includes('fintech') ||
      combined.includes('rekening') ||
      combined.includes('saldo') ||
      combined.includes('transfer') ||
      domainHost.includes('bca') ||
      domainHost.includes('mandiri')
    ) {
      whatIsIt = `Website ini adalah Portal Layanan Finansial & Perbankan Digital yang melayani transaksi keuangan, manajemen rekening nasabah, atau produk investasi online.`;
      functions = [
        `Menyediakan akses layanan transaksi uang, cek saldo, dan transfer perbankan online yang aman.`,
        `Menampilkan rincian produk tabungan, pinjaman usaha, asuransi, atau instrumen investasi.`,
        `Memberikan panduan keamanan transaksi dan pusat bantuan nasabah resmi.`
      ];
      forWhat = [
        `Nasabah: Melakukan transaksi keuangan dan memantau mutasi rekening tanpa harus antre di kantor cabang.`,
        `Calon Nasabah: Mencari syarat pembukaan rekening baru atau pengajuan fasilitas pinjaman.`
      ];
      whatCanYouDo = [
        `Login ke portal internet banking untuk transfer atau pembayaran`,
        `Melihat simulasi cicilan pinjaman atau bunga deposito`,
        `Menghubungi layanan nasabah resmi jika ada kendala rekening`
      ];
      category = 'Layanan Finansial & Perbankan Digital (Fintech)';
      targetAudience = 'Nasabah perbankan, pelaku bisnis, dan masyarakat yang bertransaksi keuangan';
    }
    // 7. General Dynamic Fallback
    else {
      const cleanDesc = (metaDesc || ogDesc || '').length > 15 ? (metaDesc || ogDesc) : (h1Matches[0] || title);
      const brandName = title.split(/[-–|]/)[0].trim() || domainHost;
      whatIsIt = `Website ini adalah situs web resmi milik ${brandName}. Halaman ini hadir untuk menyajikan layanan dan informasi: "${cleanDesc}".`;
      functions = [
        `Menyajikan informasi dan konten digital utama seputar "${cleanDesc}".`,
        `Menjadi pusat rujukan resmi bagi publik untuk mengenal layanan dan profil ${brandName}.`,
        `Menyediakan sarana komunikasi digital antara pengelola website dengan para pengunjungnya.`
      ];
      forWhat = [
        `Pengunjung / Publik: Mencari tahu informasi akurat langsung dari sumber resmi website ini.`,
        `Pengguna Layanan: Mengakses fasilitas dan halaman digital yang disediakan oleh pengelola situs.`
      ];
      whatCanYouDo = [
        `Membaca konten dan informasi yang dipublikasikan di halaman web`,
        `Menjelajahi menu navigasi dan fasilitas online yang disediakan`,
        `Melihat informasi kontak dan media penghubung resmi pemilik situs`
      ];
      category = 'Situs Informasi & Layanan Web Publik';
      targetAudience = 'Masyarakat umum, pengguna internet, dan pencari informasi terkait';
    }
  }

  res.json({
    targetInput: rawTarget,
    targetUrl,
    finalUrl,
    httpStatus: `${status} ${statusText}`,
    statusCode: status,
    elapsedMs,
    server: serverHeader,
    contentType,
    protocol: usedProtocol,
    metadata: {
      title,
      description: metaDesc || ogDesc || null,
      ogTitle: ogTitle || null,
      ogSiteName: ogSiteName || null,
      ogType: ogType || null,
      ogImage: ogImage || null,
      generator: generator || null,
      keywords: keywords ? keywords.split(',').map((k: string) => k.trim()) : [],
      headings: {
        h1: h1Matches,
        h2: h2Matches
      }
    },
    intel: {
      whatIsIt,
      functions,
      forWhat,
      whatCanYouDo,
      purpose: whatIsIt,
      keyFeatures: whatCanYouDo,
      category,
      targetAudience,
      entityOrBrand,
      safetyAssessment,
      engine: analysisEngine
    }
  });
});

// --- Server Lifecycle & Vite Middlewares ---
async function startServer() {
  if (!isProd) {
    app.get('/api/dev-export/:token', (req, res) => {
      const tokenPath = '/tmp/.atrix_export_token';
      const zipPath = '/tmp/atrix-os-complete.zip';
      if (!fs.existsSync(tokenPath) || !fs.existsSync(zipPath)) {
        return res.status(404).send('Download link expired or already consumed.');
      }
      const expected = fs.readFileSync(tokenPath, 'utf8').trim();
      const provided = String(req.params.token || '');
      if (
        expected.length !== provided.length ||
        !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(provided))
      ) {
        return res.status(403).send('Invalid export token.');
      }
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="atrix-os-complete.zip"');
      res.setHeader('Cache-Control', 'no-store');
      if (req.method === 'HEAD') {
        res.setHeader('Content-Length', String(fs.statSync(zipPath).size));
        return res.status(200).end();
      }
      res.sendFile(zipPath, (err) => {
        if (!err) {
          setTimeout(() => {
            try { fs.unlinkSync(zipPath); } catch {}
            try { fs.unlinkSync(tokenPath); } catch {}
          }, 30000);
        }
      });
    });

    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, () => {
    console.log(`ATRIX Terminal server listening on http://0.0.0.0:${PORT} (${isProd ? 'production' : 'development'})`);
  });
}

if (process.env.ATRIX_CLI_EMBEDDED !== '1' && process.env.VERCEL !== '1') {
  startServer().catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}
