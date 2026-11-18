#!/usr/bin/env node
import readline from 'readline';
import http from 'http';
import type { AddressInfo } from 'net';

// Prevent server.ts from binding port 3000 or loading Vite in CLI mode
process.env.ATRIX_CLI_EMBEDDED = '1';

// In-memory localStorage polyfill for Node.js/Termux CLI
const memoryStorage = new Map<string, string>();
if (typeof (globalThis as any).localStorage === 'undefined') {
  (globalThis as any).localStorage = {
    getItem: (k: string) => (memoryStorage.has(k) ? memoryStorage.get(k)! : null),
    setItem: (k: string, v: string) => {
      memoryStorage.set(k, String(v));
    },
    removeItem: (k: string) => {
      memoryStorage.delete(k);
    },
    clear: () => {
      memoryStorage.clear();
    },
  };
}

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  bred: '\x1b[1;31m',
  green: '\x1b[32m',
  bgreen: '\x1b[1;32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bcyan: '\x1b[1;36m',
  white: '\x1b[37m',
  bwhite: '\x1b[1;37m',
};

const ATRIX_BANNER = `${C.bred}
const ATRIX_BANNER = `${C.bred}
   ▄▄▟███████▄
 ▀▀▀▀▀▀█████▙
      ▄███████▖
    ▄█████████████
    ▄█████████▛▜██▙
   ▐█▛▜████████▄ ▝▀▚
   ▐▀ ▐██▜███████▄
      ▐██  ▀██████▙▖
       ▝▜ ▐▄ ▀██████▙
          ▐██▄███████
          ▐███████▌▜█▌
           ▀█▌▀████ ▝▜
            ▝▘ ▐███▌
               ▝████
                ▝█▝█▌
                   ▐█
                    ▝▌
──────────────────────
     ATRIX TOOLS${C.reset}
${C.dim}Cyber Security, OSINT & Recon Toolkit (Termux Ready)${C.reset}
${C.dim}Ketik 'help' untuk daftar perintah, 'clear' bersihkan layar, 'exit' keluar.${C.reset}
`;

function parseArgs(raw: string): string[] {
  const args: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (current) {
        args.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current) args.push(current);
  return args;
}

const CLI_COMMANDS = [
  'help', 'clear', 'cls', 'logo', 'exit', 'quit',
  'urlscan', 'scanurl', 'urlcheck', 'linkscan',
  'intel', 'intelligence', 'osint',
  'nmap', 'portscan', 'port', 'ssl', 'cert', 'headers', 'sec-headers',
  'whois', 'subdomains', 'cve', 'dns', 'nslookup', 'dig', 'rdns',
  'ip', 'myip', 'ping', 'curl', 'wayback', 'archive',
  'sherlock', 'stalk', 'github', 'ghrepos', 'ghemail', 'email', 'gravatar', 'phone',
  'geo', 'revgeo', 'country', 'who', 'tools', 'dork', 'search', 'ts',
  'info', 'siteinfo', 'webinfo', 'techstack', 'webtech', 'emailsec', 'dmarc', 'robots', 'securitytxt', 'cors', 'httpmethods',
  'subtakeover', 'takeover', 'bounty', 'vdp', 'cvss', 'report', 'triage',
  'wa-protect', 'wa-doxx', 'wa-rescue', 'wa-check', 'wa', 'whatsapp', 'wa-link',
  'crack', 'hash', 'hashid', 'base64', 'b64', 'hex', 'rot13', 'urlencode', 'urldecode', 'jwt', 'passcheck', 'subnet', 'cidr',
  'ctf', 'strings', 'binwalk', 'lomba',
  'wireshark', 'tshark', 'metasploit', 'msfconsole', 'burpsuite', 'burp', 'openvas', 'nikto', 'hashcat', 'sqlmap', 'aircrack', 'aircrack-ng', 'john'
];

function getCliHelp(): string {
  return `ATRIX CLI - CYBER SECURITY & OSINT TOOLKIT
==============================================================
[ URL & THREAT INTELLIGENCE (REAL-TIME) ]
  urlscan <url>                : Scan URL (Redirect tracer, Phishing, SSL, Headers, HTML)
  intel [ip|domain|email] <t>  : Threat Intelligence & Skor Keamanan (0-100)

[ NETWORK & DOMAIN RECON (REAL-TIME) ]
  nmap [mode] <target> [ports] : Port scanner (basic|quick|deep|web|vuln|ping)
  portscan <host>              : Fast TCP port scan
  ip [ip|domain] / myip        : IP publik, GeoIP, ASN, ISP & Reverse DNS
  dns <domain> [A|MX|TXT|NS]   : DNS records lookup
  rdns <ipv4>                  : Reverse DNS (PTR) lookup
  ping <host>                  : TCP reachability & latency test
  whois <domain>               : Domain registration & RDAP info
  subdomains <domain>          : Passive (crt.sh) + Active DNS subdomain scan
  headers <url>                : HTTP security headers grade (HSTS, CSP, XFO)
  ssl <host>                   : Live TLS/SSL certificate & expiry inspector
  curl [-I] [-X POST] <url>    : HTTP client request
  cve <query>                  : NIST NVD CVE vulnerability search
  wayback <url>                : Internet Archive Wayback Machine snapshot

[ WEB & BUG BOUNTY AUDIT (REAL-TIME) ]
  info <url>                   : Analisis fungsi, kategori & keamanan website
  techstack <domain>           : Fingerprinting teknologi server & framework
  emailsec <domain>            : Audit SPF, DMARC & proteksi spoofing
  robots <domain>              : Cek robots.txt & security.txt
  cors <url>                   : Uji misconfiguration CORS & HTTP methods
  subtakeover <domain>         : Cek potensi Subdomain Takeover
  bounty <domain>              : Cari Bug Bounty / VDP program & scope
  cvss <vector>                : Kalkulator skor CVSS
  report <title>               : Generator template laporan bug bounty

[ OSINT, PEOPLE & WHATSAPP PRIVACY ]
  sherlock <user> / stalk <u>  : Cek username di 16 platform secara langsung
  github <user> / ghrepos <u>  : Profil & repo GitHub + ghemail <user>
  email <addr> / gravatar <e>  : Validasi MX, burner check & profil Gravatar
  phone <num> / geo <city>     : Analisis nomor telepon / geocoding kota
  wa-check <no> / wa-protect   : Audit keamanan nomor WA & panduan anti-doxxing

[ CRYPTO, HASH & CTF ]
  crack <hash>                 : Hash dictionary recovery (MD5/SHA1/SHA256)
  hash <algo> <text>           : Hitung hash (sha256|sha512|sha1|md5)
  hashid <hash>                : Identifikasi tipe algoritma hash
  base64 / hex / rot13 / url*  : Encoder / Decoder cepat
  jwt <token>                  : Decode header, payload & expiry JWT
  passcheck <password>         : Cek entropy & estimasi waktu brute-force
  subnet <ip/cidr>             : Kalkulator IPv4 subnet & wildcard
  ctf / strings / binwalk      : Modul latihan CTF & forensik

[ KONTROL TERMINAL ]
  clear / logo / exit          : Bersihkan layar / tampilkan banner / keluar
==============================================================`;
}

async function startCli() {
  // Dynamically load server after ATRIX_CLI_EMBEDDED is set
  const { app } = await import('./server.ts');
  const server: http.Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const addr = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  // Route relative /api/* fetches inside cyberCommands to embedded loopback server
  const nativeFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = ((input: any, init?: RequestInit) => {
    if (typeof input === 'string' && input.startsWith('/')) {
      return nativeFetch(`${baseUrl}${input}`, init);
    }
    if (input instanceof URL && input.origin === 'null') {
      return nativeFetch(`${baseUrl}${input.pathname}${input.search}`, init);
    }
    return nativeFetch(input, init);
  }) as typeof fetch;

  const cyberCmds = await import('./src/utils/cyberCommands.ts');
  const crypto = await import('./src/utils/cryptoUtils.ts');

  const addLine: import('./src/utils/cyberCommands.ts').OutputAdder = (type, content) => {
    if (type === 'error') {
      console.log(`${C.bred}${content}${C.reset}`);
    } else if (type === 'system') {
      console.log(`${C.cyan}${content}${C.reset}`);
    } else if (type === 'ascii' || type === 'logo') {
      console.log(`${C.bwhite}${content}${C.reset}`);
    } else {
      console.log(content);
    }
  };

  async function runCommand(rawInput: string): Promise<'continue' | 'exit'> {
    const trimmed = rawInput.trim();
    if (!trimmed) return 'continue';

    const cleanArgs = parseArgs(trimmed);
    const cmd = cleanArgs[0]?.toLowerCase() || '';

    switch (cmd) {
      case 'exit':
      case 'quit':
        return 'exit';

      case 'clear':
      case 'cls':
        process.stdout.write('\x1b[2J\x1b[H');
        return 'continue';

      case 'logo':
        console.log(ATRIX_BANNER);
        return 'continue';

      case 'help':
      case '?':
        console.log(getCliHelp());
        return 'continue';

      case 'urlscan':
      case 'scanurl':
      case 'urlcheck':
      case 'linkscan':
        await cyberCmds.handleUrlScanCommand(cleanArgs, addLine);
        return 'continue';

      case 'intel':
      case 'intelligence':
      case 'osint':
        await cyberCmds.handleIntelCommand(cleanArgs, addLine);
        return 'continue';

      case 'nmap':
        await cyberCmds.handleNmapCommand(cleanArgs, addLine);
        return 'continue';

      case 'portscan':
      case 'port': {
        const host = cleanArgs[1];
        if (!host) {
          addLine('error', 'Usage: portscan <host>');
          return 'continue';
        }
        addLine('system', `Scanning target: ${host}...`);
        const res = await fetch('/api/security/portscan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host })
        });
        const data = await res.json();
        if (!res.ok) {
          addLine('error', data.error || 'Port scan failed');
          return 'continue';
        }
        let rows = 'PORT      STATE       SERVICE     LATENCY\n';
        data.results.forEach((r: any) => {
          rows += `${`${r.port}/tcp`.padEnd(10)}${String(r.status).toUpperCase().padEnd(12)}${String(r.service).padEnd(12)}${r.timeMs}ms\n`;
        });
        addLine('output', `Target: ${data.host} | Duration: ${data.timeMs}ms\n${rows}`);
        return 'continue';
      }

      case 'headers':
      case 'sec-headers': {
        const target = cleanArgs[1];
        if (!target) {
          addLine('error', 'Usage: headers <url>');
          return 'continue';
        }
        const res = await fetch('/api/security/headers', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: target })
        });
        const data = await res.json();
        if (!res.ok) {
          addLine('error', data.error || 'Headers audit failed');
          return 'continue';
        }
        let out = `Target: ${data.url} | Server: ${data.server} | Grade: ${data.grade} (${data.score}/100)\n`;
        data.checks.forEach((c: any) => {
          out += `${c.present ? '[PASS]' : '[FAIL]'} ${c.name}: ${c.present ? c.value : 'MISSING'}\n`;
        });
        addLine('output', out);
        return 'continue';
      }

      case 'ssl':
      case 'cert': {
        const host = cleanArgs[1];
        if (!host) {
          addLine('error', 'Usage: ssl <host>');
          return 'continue';
        }
        const res = await fetch('/api/security/ssl', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host })
        });
        const data = await res.json();
        if (!res.ok) {
          addLine('error', data.error || 'SSL audit failed');
          return 'continue';
        }
        addLine('output', `Host     : ${data.host}\nProtocol : ${data.protocol} (${data.cipher})\nIssuer   : ${data.issuer?.O || data.issuer?.CN}\nSubject  : ${data.subject?.CN}\nValid To : ${data.validTo} (${data.daysRemaining} days left, expired=${data.isExpired})\nSHA-256  : ${data.fingerprint256}`);
        return 'continue';
      }

      case 'whois': {
        const domain = cleanArgs[1];
        if (!domain) {
          addLine('error', 'Usage: whois <domain>');
          return 'continue';
        }
        const res = await fetch('/api/security/whois', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain })
        });
        const data = await res.json();
        if (!res.ok) addLine('error', data.error || 'WHOIS failed');
        else addLine('output', data.raw);
        return 'continue';
      }

      case 'subdomains': {
        const domain = cleanArgs[1];
        if (!domain) {
          addLine('error', 'Usage: subdomains <domain>');
          return 'continue';
        }
        addLine('system', `Scanning subdomains for ${domain}...`);
        const res = await fetch('/api/security/subdomains', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain })
        });
        const data = await res.json();
        if (!res.ok) {
          addLine('error', data.error || 'Subdomains scan failed');
          return 'continue';
        }
        let out = `Domain: ${data.domain} | Found: ${data.foundCount} (${data.timeMs}ms)\n`;
        data.subdomains.forEach((s: any) => {
          out += ` [+] ${s.subdomain.padEnd(30)} -> ${s.ips.join(', ')}\n`;
        });
        addLine('output', out);
        return 'continue';
      }

      case 'cve': {
        const query = cleanArgs.slice(1).join(' ');
        if (!query) {
          addLine('error', 'Usage: cve <query>');
          return 'continue';
        }
        const res = await fetch('/api/security/cve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query })
        });
        const data = await res.json();
        if (!res.ok) {
          addLine('error', data.error || 'CVE lookup failed');
          return 'continue';
        }
        if (!data.results?.length) {
          addLine('output', `No CVE records found for '${query}'.`);
          return 'continue';
        }
        let out = '';
        data.results.forEach((c: any) => {
          out += `[${c.id}] CVSS ${c.cvss} (${c.severity}) | ${c.published}\n  ${c.description.slice(0, 220)}...\n\n`;
        });
        addLine('output', out);
        return 'continue';
      }

      case 'dns':
      case 'nslookup':
      case 'dig': {
        const host = cleanArgs[1];
        const type = (cleanArgs[2] || 'A').toUpperCase();
        if (!host) {
          addLine('error', 'Usage: dns <host> [A|AAAA|MX|TXT|NS|CNAME]');
          return 'continue';
        }
        const res = await fetch('/api/dns', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host, type })
        });
        const data = await res.json();
        if (!res.ok) {
          addLine('error', data.error || 'DNS lookup failed');
          return 'continue';
        }
        const lines = (data.records || []).map((r: any) => `${data.host}  IN  ${data.type}  ${typeof r === 'object' ? JSON.stringify(r) : r}`);
        addLine('output', lines.join('\n') || 'No records found.');
        return 'continue';
      }

      case 'ip':
      case 'myip': {
        const target = cmd === 'myip' ? undefined : cleanArgs[1];
        const url = target ? `/api/ip?target=${encodeURIComponent(target)}` : '/api/ip';
        const res = await fetch(url);
        const data = await res.json();
        if (!res.ok) {
          addLine('error', data.error || 'IP lookup failed');
          return 'continue';
        }
        const flags = data.securityFlags || {};
        const flagTags = [
          flags.isProxy ? 'PROXY/VPN[!]' : null,
          flags.isHosting ? 'HOSTING/CLOUD' : null,
          flags.isMobile ? 'MOBILE' : null,
          flags.isAnycast ? 'ANYCAST/CDN' : null,
          flags.isBogon ? 'PRIVATE/BOGON' : null
        ].filter(Boolean);
        let out = `IP Address    : ${data.ip} (${data.ipVersion || 'IPv4'})${data.target ? ` [Target: ${data.target}]` : ''}
Location      : ${data.city}, ${data.region}, ${data.country} (${data.country_code}) [${data.continent || 'N/A'}]${data.postal && data.postal !== 'N/A' ? ` ZIP: ${data.postal}` : ''}
Coordinates   : ${data.coordinates || 'N/A'}${data.osmUrl ? `\nMap Link      : ${data.osmUrl}` : ''}
ASN / BGP     : ${data.asn || 'N/A'} | Prefix: ${data.bgpPrefix || 'N/A'}
ISP / Org     : ${data.isp || data.org} (${data.org})
Network Type  : ${data.networkType || 'ISP'}${flagTags.length > 0 ? ` [${flagTags.join(', ')}]` : ''}
Timezone      : ${data.timezone}
Geo Consensus : ${data.consensus || 'Verified'}`;
        if (data.reverseDns?.length) out += `\nReverse DNS   : ${data.reverseDns.join(', ')}`;
        if (data.providersUsed?.length) out += `\nGeo Sources   : ${data.providersUsed.join(' + ')}`;
        addLine('output', out);
        return 'continue';
      }

      case 'ping': {
        const host = cleanArgs[1];
        if (!host) {
          addLine('error', 'Usage: ping <host>');
          return 'continue';
        }
        const res = await fetch('/api/ping', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host })
        });
        const data = await res.json();
        if (!res.ok) {
          addLine('error', data.error || 'Ping failed');
          return 'continue';
        }
        data.samples.forEach((ms: number, i: number) => {
          addLine('output', ms >= 0 ? `64 bytes from ${data.host}: seq=${i + 1} time=${ms} ms` : `Timeout seq=${i + 1}`);
        });
        addLine('output', `--- ${data.host} --- loss=${data.packetLoss}% min/avg/max=${data.min}/${data.avg}/${data.max} ms`);
        return 'continue';
      }

      case 'curl': {
        const args = cleanArgs.slice(1);
        let url = '';
        let method = 'GET';
        let headersOnly = false;
        let postData: string | undefined;
        for (let i = 0; i < args.length; i++) {
          if (args[i] === '-I' || args[i] === '--head') headersOnly = true;
          else if ((args[i] === '-X' || args[i] === '--request') && args[i + 1]) method = args[++i].toUpperCase();
          else if ((args[i] === '-d' || args[i] === '--data') && args[i + 1]) { postData = args[++i]; if (method === 'GET') method = 'POST'; }
          else if (!args[i].startsWith('-')) url = args[i];
        }
        if (!url) {
          addLine('error', 'Usage: curl [-I] [-X METHOD] [-d data] <url>');
          return 'continue';
        }
        const res = await fetch('/api/curl', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, method, body: postData })
        });
        const result = await res.json();
        if (!res.ok) {
          addLine('error', result.error || 'curl failed');
          return 'continue';
        }
        if (headersOnly) {
          let h = `HTTP/1.1 ${result.status} ${result.statusText}\n`;
          for (const [k, v] of Object.entries(result.headers || {})) h += `${k}: ${v}\n`;
          addLine('output', h);
        } else {
          addLine('output', result.isJson ? JSON.stringify(result.data, null, 2) : String(result.data));
        }
        return 'continue';
      }

      case 'rdns': await cyberCmds.handleRdnsCommand(cleanArgs, addLine); return 'continue';
      case 'wayback': case 'archive': await cyberCmds.handleWaybackCommand(cleanArgs, addLine); return 'continue';
      case 'tools': cyberCmds.handleToolsCommand(cleanArgs, addLine); return 'continue';
      case 'who': await cyberCmds.handleWhoCommand(cleanArgs, addLine); return 'continue';
      case 'sherlock': case 'stalk': await cyberCmds.handleSherlockCommand(cleanArgs, addLine); return 'continue';
      case 'github': await cyberCmds.handleGithubCommand(cleanArgs, addLine); return 'continue';
      case 'ghrepos': await cyberCmds.handleGhReposCommand(cleanArgs, addLine); return 'continue';
      case 'ghemail': await cyberCmds.handleGhEmailCommand(cleanArgs, addLine); return 'continue';
      case 'email': await cyberCmds.handleEmailCommand(cleanArgs, addLine); return 'continue';
      case 'gravatar': await cyberCmds.handleGravatarCommand(cleanArgs, addLine); return 'continue';
      case 'phone': cyberCmds.handlePhoneCommand(cleanArgs, addLine); return 'continue';
      case 'geo': await cyberCmds.handleGeoCommand(cleanArgs, addLine); return 'continue';
      case 'revgeo': await cyberCmds.handleRevGeoCommand(cleanArgs, addLine); return 'continue';
      case 'country': await cyberCmds.handleCountryCommand(cleanArgs, addLine); return 'continue';
      case 'dork': cyberCmds.handleDorkCommand(cleanArgs, addLine); return 'continue';
      case 'search': cyberCmds.handleSearchCommand(cleanArgs, addLine); return 'continue';
      case 'ts': cyberCmds.handleTsCommand(cleanArgs, addLine); return 'continue';
      case 'info': case 'siteinfo': case 'webinfo': await cyberCmds.handleInfoCommand(cleanArgs, addLine); return 'continue';
      case 'techstack': case 'webtech': await cyberCmds.handleTechstackCommand(cleanArgs, addLine); return 'continue';
      case 'emailsec': case 'dmarc': await cyberCmds.handleEmailSecCommand(cleanArgs, addLine); return 'continue';
      case 'robots': case 'securitytxt': await cyberCmds.handleCrawlersCommand(cleanArgs, addLine); return 'continue';
      case 'cors': case 'httpmethods': await cyberCmds.handleCorsCommand(cleanArgs, addLine); return 'continue';
      case 'subtakeover': case 'takeover': await cyberCmds.handleSubtakeoverCommand(cleanArgs, addLine); return 'continue';
      case 'bounty': case 'vdp': await cyberCmds.handleBountyCommand(cleanArgs, addLine); return 'continue';
      case 'cvss': cyberCmds.handleCvssCommand(cleanArgs, addLine); return 'continue';
      case 'report': case 'triage': cyberCmds.handleReportCommand(cleanArgs, addLine); return 'continue';
      case 'wa-protect': case 'wa-doxx': case 'wa-rescue': case 'wa-aman': cyberCmds.handleWaProtectCommand(cleanArgs, addLine); return 'continue';
      case 'wa-check': case 'wa': case 'whatsapp': cyberCmds.handleWaCheckCommand(cleanArgs, addLine); return 'continue';
      case 'wa-link': case 'walink': cyberCmds.handleWaLinkCommand(cleanArgs, addLine); return 'continue';
      case 'crack': await cyberCmds.handleCrackCommand(cleanArgs, addLine); return 'continue';
      case 'ctf': case 'ctfd': cyberCmds.handleCtfCommand(cleanArgs, addLine); return 'continue';
      case 'strings': cyberCmds.handleStringsCommand(cleanArgs, addLine); return 'continue';
      case 'binwalk': cyberCmds.handleBinwalkCommand(cleanArgs, addLine); return 'continue';
      case 'lomba': case 'cyber-cheat': cyberCmds.handleLombaCommand(cleanArgs, addLine); return 'continue';
      case 'wireshark': case 'tshark': cyberCmds.handleWiresharkCommand(cleanArgs, addLine); return 'continue';
      case 'metasploit': case 'msfconsole': cyberCmds.handleMetasploitCommand(cleanArgs, addLine); return 'continue';
      case 'burpsuite': case 'burp': cyberCmds.handleBurpCommand(cleanArgs, addLine); return 'continue';
      case 'openvas': await cyberCmds.handleOpenVASCommand(cleanArgs, addLine); return 'continue';
      case 'nikto': cyberCmds.handleNiktoCommand(cleanArgs, addLine); return 'continue';
      case 'hashcat': await cyberCmds.handleHashcatCommand(cleanArgs, addLine); return 'continue';
      case 'sqlmap': cyberCmds.handleSqlmapCommand(cleanArgs, addLine); return 'continue';
      case 'aircrack': case 'aircrack-ng': cyberCmds.handleAircrackCommand(cleanArgs, addLine); return 'continue';
      case 'john': await cyberCmds.handleJohnCommand(cleanArgs, addLine); return 'continue';

      case 'hash': {
        if (cleanArgs.length < 3) {
          addLine('error', 'Usage: hash <sha256|sha512|sha1|md5> <text>');
          return 'continue';
        }
        const a = cleanArgs[1].toLowerCase();
        const algo = a === 'sha512' ? 'SHA-512' : a === 'sha1' ? 'SHA-1' : a === 'md5' ? 'MD5' : 'SHA-256';
        addLine('output', `${algo}: ${await crypto.computeHash(algo, cleanArgs.slice(2).join(' '))}`);
        return 'continue';
      }
      case 'hashid': {
        if (!cleanArgs[1]) { addLine('error', 'Usage: hashid <hash>'); return 'continue'; }
        const info = crypto.identifyHash(cleanArgs[1]);
        addLine('output', `Length: ${info.length} | Charset: ${info.charset}\nPossible: ${info.possibleTypes.join(', ')}`);
        return 'continue';
      }
      case 'base64':
      case 'b64': {
        const mode = cleanArgs[1]?.toLowerCase();
        const txt = cleanArgs.slice(2).join(' ');
        if (!txt) { addLine('error', 'Usage: base64 <encode|decode> <text>'); return 'continue'; }
        addLine('output', mode === 'decode' || mode === '-d' ? crypto.base64Decode(txt) : crypto.base64Encode(txt));
        return 'continue';
      }
      case 'hex': {
        const mode = cleanArgs[1]?.toLowerCase();
        const txt = cleanArgs.slice(2).join(' ');
        if (!txt) { addLine('error', 'Usage: hex <encode|decode> <text>'); return 'continue'; }
        addLine('output', mode === 'decode' || mode === '-d' ? crypto.hexDecode(txt) : crypto.hexEncode(txt));
        return 'continue';
      }
      case 'rot13':
        addLine('output', crypto.rot13(cleanArgs.slice(1).join(' ')));
        return 'continue';
      case 'urlencode':
        addLine('output', crypto.urlEncode(cleanArgs.slice(1).join(' ')));
        return 'continue';
      case 'urldecode':
        addLine('output', crypto.urlDecode(cleanArgs.slice(1).join(' ')));
        return 'continue';
      case 'jwt':
        if (!cleanArgs[1]) { addLine('error', 'Usage: jwt <token>'); return 'continue'; }
        try {
          const p = crypto.parseJwt(cleanArgs[1]);
          addLine('output', `HEADER:\n${JSON.stringify(p.header, null, 2)}\nPAYLOAD:\n${JSON.stringify(p.payload, null, 2)}\nEXPIRED: ${p.isExpired ? 'YES' : 'NO'}`);
        } catch (e: any) { addLine('error', e.message); }
        return 'continue';
      case 'passcheck':
        if (!cleanArgs[1]) { addLine('error', 'Usage: passcheck <password>'); return 'continue'; }
        {
          const r = crypto.analyzePassword(cleanArgs.slice(1).join(' '));
          addLine('output', `Rating: ${r.rating} | Entropy: ${r.entropy} bits | Crack Time: ${r.crackTime}`);
        }
        return 'continue';
      case 'subnet':
      case 'cidr':
        if (!cleanArgs[1]) { addLine('error', 'Usage: subnet <ip/cidr>'); return 'continue'; }
        try {
          const s = crypto.calculateSubnet(cleanArgs[1]);
          addLine('output', `CIDR: ${s.cidr} | Netmask: ${s.netmask} | Network: ${s.network} | Broadcast: ${s.broadcast} | Usable: ${s.firstUsable} - ${s.lastUsable} (${s.usableHosts} hosts)`);
        } catch (e: any) { addLine('error', e.message); }
        return 'continue';

      default:
        addLine('error', `Perintah '${cmd}' tidak dikenal. Ketik 'help' untuk melihat semua fitur.`);
        return 'continue';
    }
  }

  // One-shot CLI mode: `tsx cli.ts urlscan https://example.com`
  const cliArgs = process.argv.slice(2);
  if (cliArgs.length > 0) {
    try {
      await runCommand(cliArgs.join(' '));
    } finally {
      server.close();
    }
    return;
  }

  // Interactive Termux CLI mode
  process.stdout.write('\x1b[2J\x1b[H');
  console.log(ATRIX_BANNER);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: `${C.bred}atrix${C.reset}:${C.bcyan}~${C.reset}$ `,
    completer: (line: string) => {
      const hits = CLI_COMMANDS.filter((c) => c.startsWith(line.trim().toLowerCase()));
      return [hits.length ? hits : CLI_COMMANDS, line];
    },
  });

  rl.prompt();

  rl.on('line', async (line) => {
    rl.pause();
    try {
      const state = await runCommand(line);
      if (state === 'exit') {
        rl.close();
        return;
      }
    } catch (err: any) {
      console.error(`${C.bred}Error: ${err?.message || err}${C.reset}`);
    }
    rl.prompt();
  });

  rl.on('close', () => {
    console.log(`\n${C.dim}ATRIX CLI closed.${C.reset}`);
    server.close();
    process.exit(0);
  });
}

startCli().catch((err) => {
  console.error('Fatal CLI error:', err);
  process.exit(1);
});
