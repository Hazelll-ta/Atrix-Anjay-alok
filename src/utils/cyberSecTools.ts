// Comprehensive Cyber Security, OSINT, Network Recon, and System Diagnostics Toolkit for ATRIX OS

export interface DorkItem {
  category: string;
  dorks: { query: string; purpose: string }[];
}

export const generateDorks = (target: string): DorkItem[] => {
  const cleanTarget = target.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  const domain = cleanTarget || 'example.com';

  return [
    {
      category: 'Exposed Credentials & Sensitive Files',
      dorks: [
        { query: `site:${domain} ext:env OR ext:yml OR ext:yaml OR ext:ini`, purpose: 'Environment & config credentials' },
        { query: `site:${domain} filetype:sql OR filetype:db OR filetype:sqlite`, purpose: 'Database dumps & SQL backups' },
        { query: `site:${domain} filetype:log "password" OR "token" OR "secret"`, purpose: 'Exposed application runtime logs' },
        { query: `site:${domain} filetype:json "private_key" OR "client_secret"`, purpose: 'Exposed API service credentials' },
        { query: `site:${domain} intext:"id_rsa" OR intext:"BEGIN RSA PRIVATE KEY"`, purpose: 'Leaked SSH private keys' }
      ]
    },
    {
      category: 'Admin Portals & Login Dashboards',
      dorks: [
        { query: `site:${domain} inurl:admin OR inurl:login OR inurl:dashboard`, purpose: 'Direct access to admin panels' },
        { query: `site:${domain} inurl:wp-login.php OR inurl:wp-admin`, purpose: 'WordPress administrative portals' },
        { query: `site:${domain} inurl:phpmyadmin OR intext:"phpMyAdmin"`, purpose: 'phpMyAdmin web database management' },
        { query: `site:${domain} inurl:cpanel OR inurl:webmail`, purpose: 'cPanel & webmail hosting interfaces' }
      ]
    },
    {
      category: 'Information Disclosure & Directory Traversal',
      dorks: [
        { query: `site:${domain} intitle:"Index of /" OR intitle:"Index of /backup"`, purpose: 'Open web server directory listings' },
        { query: `site:${domain} inurl:.git OR inurl:.svn OR inurl:.hg`, purpose: 'Exposed version control repositories' },
        { query: `site:${domain} ext:php "phpinfo()" OR "System" "Build Date"`, purpose: 'phpinfo() environment disclosure' },
        { query: `site:${domain} ext:bkp OR ext:bak OR ext:old OR ext:backup`, purpose: 'Backup files left in webroot' },
        { query: `site:${domain} inurl:api/v1 OR inurl:api/v2 OR inurl:swagger OR inurl:openapi`, purpose: 'Exposed REST & Swagger API endpoints' }
      ]
    },
    {
      category: 'SQL Errors & Software Vulnerabilities',
      dorks: [
        { query: `site:${domain} intext:"syntax error in SQL statement" OR intext:"mysql_fetch_array"`, purpose: 'Vulnerable SQL query errors' },
        { query: `site:${domain} intext:"Warning: mysql_" OR intext:"PostgreSQL query failed"`, purpose: 'Database backend connection leakage' }
      ]
    }
  ];
};

export const getSocialsList = (username: string) => {
  const u = encodeURIComponent(username.trim().replace(/^@/, ''));
  return [
    { name: 'GitHub', url: `https://github.com/${u}` },
    { name: 'X / Twitter', url: `https://x.com/${u}` },
    { name: 'Instagram', url: `https://instagram.com/${u}` },
    { name: 'Reddit', url: `https://reddit.com/user/${u}` },
    { name: 'TikTok', url: `https://tiktok.com/@${u}` },
    { name: 'Telegram', url: `https://t.me/${u}` },
    { name: 'YouTube', url: `https://youtube.com/@${u}` },
    { name: 'Twitch', url: `https://twitch.tv/${u}` },
    { name: 'Medium', url: `https://medium.com/@${u}` },
    { name: 'Pinterest', url: `https://pinterest.com/${u}` },
    { name: 'Spotify', url: `https://open.spotify.com/user/${u}` },
    { name: 'Steam', url: `https://steamcommunity.com/id/${u}` },
    { name: 'GitLab', url: `https://gitlab.com/${u}` },
    { name: 'Docker Hub', url: `https://hub.docker.com/u/${u}` },
    { name: 'HackerNews', url: `https://news.ycombinator.com/user?id=${u}` },
    { name: 'Keybase', url: `https://keybase.io/${u}` },
    { name: 'Behance', url: `https://behance.net/${u}` },
    { name: 'Dribbble', url: `https://dribbble.com/${u}` },
    { name: 'Linktree', url: `https://linktr.ee/${u}` },
    { name: 'Substack', url: `https://${u}.substack.com` },
    { name: 'Threads', url: `https://threads.net/@${u}` },
    { name: 'Mastodon', url: `https://mastodon.social/@${u}` },
    { name: 'Patreon', url: `https://patreon.com/${u}` },
    { name: 'PayPal.me', url: `https://paypal.me/${u}` },
    { name: 'SoundCloud', url: `https://soundcloud.com/${u}` },
    { name: 'DeviantArt', url: `https://${u}.deviantart.com` },
    { name: 'Gravatar', url: `https://gravatar.com/${u}` },
    { name: 'Codecademy', url: `https://codecademy.com/profiles/${u}` },
    { name: 'ProductHunt', url: `https://producthunt.com/@${u}` },
    { name: 'Bandcamp', url: `https://${u}.bandcamp.com` }
  ];
};

export const getJumpLinks = (target: string) => {
  const clean = target.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(clean);

  return [
    { name: 'Shodan (IoT & Service Search)', url: isIp ? `https://www.shodan.io/host/${clean}` : `https://www.shodan.io/search?query=hostname%3A${clean}` },
    { name: 'VirusTotal (Malware & URL Scanner)', url: `https://www.virustotal.com/gui/search/${clean}` },
    { name: 'URLScan.io (Web Page Sandbox)', url: `https://urlscan.io/search/#${clean}` },
    { name: 'Censys (Attack Surface Intel)', url: isIp ? `https://search.censys.io/hosts/${clean}` : `https://search.censys.io/search?q=${clean}` },
    { name: 'SecurityTrails (Historical DNS & Subdomains)', url: `https://securitytrails.com/domain/${clean}/dns` },
    { name: 'GreyNoise (Internet Noise & Scanner Intel)', url: isIp ? `https://viz.greynoise.io/ip/${clean}` : `https://viz.greynoise.io/query?gnql=${clean}` },
    { name: 'crt.sh (Certificate Transparency Logs)', url: `https://crt.sh/?q=${clean}` },
    { name: 'Wayback Machine (Archive.org Historical Cache)', url: `https://web.archive.org/web/*/${clean}` }
  ];
};

export const analyzePhone = (input: string) => {
  const raw = input.trim();
  const digits = raw.replace(/\D/g, '');

  const countryDialCodes: Record<string, { country: string; flag: string }> = {
    '62': { country: 'Indonesia', flag: '🇮🇩' },
    '1': { country: 'USA / Canada', flag: '🇺🇸' },
    '44': { country: 'United Kingdom', flag: '🇬🇧' },
    '60': { country: 'Malaysia', flag: '🇲🇾' },
    '65': { country: 'Singapore', flag: '🇸🇬' },
    '61': { country: 'Australia', flag: '🇦🇺' },
    '81': { country: 'Japan', flag: '🇯🇵' },
    '82': { country: 'South Korea', flag: '🇰🇷' },
    '86': { country: 'China', flag: '🇨🇳' },
    '91': { country: 'India', flag: '🇮🇳' },
    '49': { country: 'Germany', flag: '🇩🇪' },
    '33': { country: 'France', flag: '🇫🇷' },
    '7': { country: 'Russia / Kazakhstan', flag: '🇷🇺' },
    '55': { country: 'Brazil', flag: '🇧🇷' },
    '966': { country: 'Saudi Arabia', flag: '🇸🇦' }
  };

  let matchedPrefix = '';
  let countryInfo = { country: 'Unknown / International', flag: '🌐' };

  for (const prefix of ['966', '62', '60', '65', '44', '49', '33', '81', '82', '86', '91', '55', '61', '1', '7']) {
    if (digits.startsWith(prefix)) {
      matchedPrefix = prefix;
      countryInfo = countryDialCodes[prefix];
      break;
    }
  }

  const formatted = raw.startsWith('+') ? `+${digits}` : `+${digits}`;

  return {
    raw,
    digits,
    formatted,
    country: countryInfo.country,
    flag: countryInfo.flag,
    dialCode: matchedPrefix ? `+${matchedPrefix}` : 'N/A',
    length: digits.length,
    validLength: digits.length >= 7 && digits.length <= 15,
    searchLinks: [
      { name: 'Google Search', url: `https://www.google.com/search?q="${formatted}"` },
      { name: 'Truecaller Lookup', url: `https://www.truecaller.com/search/${digits}` },
      { name: 'WhatsApp Direct Link', url: `https://wa.me/${digits}` },
      { name: 'Telegram Search', url: `https://t.me/+${digits}` }
    ]
  };
};

export const getBrowserFingerprint = () => {
  const n = navigator as any;
  const s = window.screen;

  let gpuRenderer = 'Standard Software / GPU';
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const dbg = (gl as any).getExtension('WEBGL_debug_renderer_info');
      if (dbg) {
        gpuRenderer = (gl as any).getParameter(dbg.UNMASKED_RENDERER_WEBGL);
      }
    }
  } catch {
    // fallback
  }

  return {
    userAgent: n.userAgent,
    platform: n.platform || 'Linux aarch64',
    language: n.language || 'en-US',
    languages: (n.languages || []).join(', '),
    hardwareConcurrency: n.hardwareConcurrency ? `${n.hardwareConcurrency} Cores` : '8 Cores',
    deviceMemory: n.deviceMemory ? `${n.deviceMemory} GiB RAM` : '4 GiB RAM',
    screenResolution: `${s.width}x${s.height} (${s.colorDepth}-bit color)`,
    windowInner: `${window.innerWidth}x${window.innerHeight}`,
    pixelRatio: window.devicePixelRatio || 1,
    touchSupport: ('ontouchstart' in window || n.maxTouchPoints > 0) ? `Yes (${n.maxTouchPoints || 1} points)` : 'No',
    cookiesEnabled: n.cookieEnabled ? 'Enabled' : 'Disabled',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    doNotTrack: n.doNotTrack === '1' ? 'Active' : 'Unspecified',
    gpuRenderer
  };
};

export async function getBatteryTelemetry(): Promise<{ level: number; charging: boolean; display: string; icon: string }> {
  try {
    const n = navigator as any;
    if (typeof n.getBattery === 'function') {
      const b = await n.getBattery();
      const pct = Math.round(b.level * 100);
      const charging = b.charging;
      const statusText = charging ? 'Charging' : 'Discharging';
      const icon = charging ? '⚡' : (pct > 20 ? '🔋' : '🪫');
      return {
        level: pct,
        charging,
        display: `${pct}% [${statusText}]`,
        icon
      };
    }
  } catch {
    // fallback
  }
  return {
    level: 76,
    charging: false,
    display: '76% [Discharging]',
    icon: '🔋'
  };
}

export const getMountedFolders = () => [
  { mountpoint: '/dev', device: 'devtmpfs', type: 'devtmpfs', options: 'rw,nosuid,relatime,size=1796128k,nr_inodes=449032,mode=755' },
  { mountpoint: '/sys', device: 'sysfs', type: 'sysfs', options: 'rw,nosuid,nodev,noexec,relatime' },
  { mountpoint: '/proc', device: 'proc', type: 'proc', options: 'rw,nosuid,nodev,noexec,relatime' },
  { mountpoint: '/dev/pts', device: 'devpts', type: 'devpts', options: 'rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000' },
  { mountpoint: '/dev/shm', device: 'tmpfs', type: 'tmpfs', options: 'rw,nosuid,nodev,size=1833504k' },
  { mountpoint: '/tmp', device: 'tmpfs', type: 'tmpfs', options: 'rw,nosuid,nodev,size=1833504k' },
  { mountpoint: '/run', device: 'tmpfs', type: 'tmpfs', options: 'rw,nosuid,nodev,mode=755,size=1833504k' },
  { mountpoint: '/sdcard', device: '/data/media/0', type: 'sdcardfs', options: 'rw,nosuid,nodev,noexec,relatime,uid=1023,gid=1023' },
  { mountpoint: '/', device: '/dev/root', type: 'ext4', options: 'rw,relatime,data=ordered' }
];

export const getDiskUsageReport = () => `Filesystem      Size  Used Avail Use% Mounted on
/dev/root        32G  5.4G   25G  18% /
devtmpfs        1.8G     0  1.8G   0% /dev
tmpfs           1.8G  1.2M  1.8G   1% /dev/shm
tmpfs           1.8G   32M  1.8G   2% /run
tmpfs           1.8G  4.0K  1.8G   1% /tmp
/data/media/0    64G   18G   46G  29% /sdcard`;

export const CYBER_TOOLS_CATALOG = [
  { id: 'nmap', name: 'Nmap', category: 'Network Scanner', desc: 'Port scanner, OS fingerprinting & NSE scripts' },
  { id: 'wireshark', name: 'Wireshark', category: 'Packet Analysis', desc: 'Deep packet inspection & protocol analyzer' },
  { id: 'metasploit', name: 'Metasploit', category: 'Exploit Framework', desc: 'Modular exploit search & payload generator' },
  { id: 'burpsuite', name: 'Burp Suite', category: 'Web Testing', desc: 'HTTP proxy interceptor, repeater & intruder fuzzing' },
  { id: 'openvas', name: 'OpenVAS', category: 'Vulnerability Scanner', desc: 'Target security vulnerability assessment & CVSS' },
  { id: 'nikto', name: 'Nikto', category: 'Web Scanner', desc: 'Web server misconfigurations & CGI script audit' },
  { id: 'hashcat', name: 'Hashcat', category: 'Password Cracking', desc: 'World fastest rule-based & GPU hash recovery' },
  { id: 'sqlmap', name: 'SQLmap', category: 'SQL Injection', desc: 'Automated SQL injection & database takeover' },
  { id: 'aircrack-ng', name: 'Aircrack-ng', category: 'WiFi Security', desc: '802.11 WEP/WPA/WPA2 capture & dictionary recovery' },
  { id: 'john', name: 'John the Ripper', category: 'Password Cracker', desc: 'Customizable dictionary & brute force recovery' },
  { id: 'snort', name: 'Snort', category: 'Intrusion Detection', desc: 'Real-time packet inspection & signature rule engine' },
  { id: 'ossec', name: 'OSSEC', category: 'Host IDS', desc: 'File integrity monitoring (FIM) & log auditor' },
  { id: 'maltego', name: 'Maltego', category: 'OSINT Intelligence', desc: 'Visual relationship mapping & entity graphing' },
  { id: 'setoolkit', name: 'SEToolkit', category: 'Social Engineering', desc: 'Spear-phishing & web credential harvester framework' },
  { id: 'autopsy', name: 'Autopsy', category: 'Digital Forensics', desc: 'Disk forensics, file carver & artifact timeline' }
];
