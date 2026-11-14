import { useState, useEffect, useRef } from 'react';
import { vfs } from '../utils/virtualFileSystem';
import {
  computeHash,
  base64Encode,
  base64Decode,
  parseJwt,
  generateUUID,
  evaluateCalc,
  lineDiff,
  analyzePassword,
  calculateSubnet,
  rot13,
  hexEncode,
  hexDecode,
  urlEncode,
  urlDecode,
  identifyHash
} from '../utils/cryptoUtils';
import { NanoEditor } from './NanoEditor';
import { TopMonitor } from './TopMonitor';
import { MatrixRain } from './MatrixRain';
import { TerminalOutputLine, NeofetchInfo } from '../types/terminal';
import * as cyberCmds from '../utils/cyberCommands';
import { getBatteryTelemetry } from '../utils/cyberSecTools';

export const ATRIX_LOGO_ASCII = `    _   _____ ____  _____ __  __
   / \\ |_   _|  _ \\|_   _\\\\ \\/ /
  / _ \\  | | | |_) | | |   \\  / 
 / ___ \\ | | |  _ <  | |   /  \\ 
/_/   \\_\\|_| |_| \\_\\ |_| /_/\\_\\ 
────────────────────────────────
       A T R I X   O S`;

export const ARCH_TRIANGLE_ASCII = `          -\`
        .o+\`
       \`ooo/
      \`+oooo:
     \`+oooooo:
     -+oooooo+:
   \`/:-:++oooo+:
  \`/++++/+++++++:
 \`/++++++++++++++:
\`/+++oooooooooooo/\`
./ooosssso++osssssso+\`
.oossssso-\`\`\`\`/ossssss+\`
-osssssso.      :ssssssso.
:osssssss/        osssso+++.
/ossssssss/        +ssssooo/-
\`/ossssso+/:-        -:/+osssso+-
\`+sso+:- \`                 \`.-/+oso:
\`++:.                           \`-/+/
.\`                                 \`/`;

export const LOGO_COLOR_PRESETS: Record<string, { label: string; hex: string }> = {
  cyan: { label: 'Arch Cyan (Default)', hex: '#06b6d4' },
  green: { label: 'Classic Matrix Green', hex: '#22c55e' },
  amber: { label: 'Warm Amber Gold', hex: '#f59e0b' },
  blue: { label: 'Electric Blue', hex: '#3b82f6' },
  purple: { label: 'Neon Violet', hex: '#a855f7' },
  red: { label: 'Alert Crimson Red', hex: '#ef4444' },
  yellow: { label: 'Electric Yellow', hex: '#eab308' },
  white: { label: 'Monochrome White', hex: '#ffffff' },
  pink: { label: 'Neon Pink', hex: '#ec4899' }
};

export const getNeofetchData = (batteryOverride?: string): NeofetchInfo => ({
  userHost: 'codak@localhost',
  os: 'Arch Linux ARM aarch64',
  host: 'Olive QRD',
  kernel: 'Linux 4.9.336-Kamui-Ksu-v1.8--g670c9e3y',
  uptime: '1 day, 13 hours, 50 mins',
  packages: '201 (pacman)',
  shell: 'zsh 5.9',
  terminal: 'xterm-256color',
  cpu: 'Cortex-A53*8 (8) @ 2.02 GHz',
  memory: '2.72 GiB / 3.51 GiB (78%)',
  swap: '1.33 GiB / 1.50 GiB (89%)',
  localIp: '192.168.1.220/24',
  battery: batteryOverride || '76% [Discharging]',
  locale: 'en_US.UTF-8'
});

const ATRIX_ASCII = `==========================================
        ATRIX OS - SYSTEM TOOLKIT        
==========================================
[1] SYSTEM INFO (neofetch)
[2] PACKAGE / SPEEDTEST (benchmark)
[3] FILESYSTEM EXPLORER (ls -la)
[4] SYSTEM MONITOR (top)
[5] NETWORK & TOOLS (curl / ping / ip)
==========================================
Type 1-5 or any command. Type 'help' for full manual.`;

export function Terminal() {
  const [currentDir, setCurrentDir] = useState<string>('/home/user');
  const [inputVal, setInputVal] = useState<string>('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [lines, setLines] = useState<TerminalOutputLine[]>([]);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [activeApp, setActiveApp] = useState<'terminal' | 'nano' | 'top' | 'matrix'>('terminal');
  const [nanoTargetFile, setNanoTargetFile] = useState<string>('');
  const [nanoInitialContent, setNanoInitialContent] = useState<string>('');
  const [fontSize, setFontSize] = useState<number>(14);
  const [logoColor, setLogoColor] = useState<string>(() => {
    return localStorage.getItem('atrix_logo_color') || '#06b6d4';
  });
  const [envVars, setEnvVars] = useState<Record<string, string>>({
    USER: 'codak',
    HOSTNAME: 'localhost',
    HOME: '/home/user',
    SHELL: '/bin/zsh',
    TERM: 'xterm-256color',
    PATH: '/bin:/usr/bin:/home/user/bin',
    OS: 'Arch Linux ARM aarch64'
  });

  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const sessionStartTime = useRef<number>(Date.now());

  const updateLogoColor = (newColor: string) => {
    setLogoColor(newColor);
    localStorage.setItem('atrix_logo_color', newColor);
  };

  const prevLinesCount = useRef<number>(0);
  const promptEndRef = useRef<HTMLDivElement>(null);

  // Focus input automatically without jumping scroll position
  useEffect(() => {
    if (activeApp === 'terminal') {
      inputRef.current?.focus({ preventScroll: true });
    }
  }, [activeApp, lines]);

  // Scroll smoothly ONLY when new output lines are generated, NEVER while user is typing
  useEffect(() => {
    if (lines.length > prevLinesCount.current) {
      const timer = setTimeout(() => {
        promptEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 30);
      prevLinesCount.current = lines.length;
      return () => clearTimeout(timer);
    }
    prevLinesCount.current = lines.length;
  }, [lines]);

  // Initial welcome message matching user's Image 1
  useEffect(() => {
    const welcomeLines: TerminalOutputLine[] = [
      {
        id: 'boot-mounts',
        type: 'ascii',
        content: `#################################\n\n[ Mouting system folders ]\n\n [ Mouting suid, dev ]\n [ Mouting /dev ]\n [ Mouting /sys ]\n [ Mouting /proc ]\n [ Mouting /dev/pts ]\n [ Mouting /dev/shm ]\n [ Mouting /tmp ]\n [ Mounting /run ]\n [ Mouting /sdcard ]\n\n[ Mouting Done! ]\n> chrooting`
      },
      {
        id: 'boot-neofetch',
        type: 'neofetch',
        content: '',
        neofetchData: getNeofetchData()
      }
    ];
    setLines(welcomeLines);
  }, []);

  const addLine = (type: TerminalOutputLine['type'], content: string, prompt?: string, color?: string, neofetchData?: NeofetchInfo) => {
    setLines(prev => [
      ...prev,
      {
        id: 'line-' + Math.random().toString(36).substring(2, 9),
        type,
        content,
        prompt,
        timestamp: Date.now(),
        color,
        neofetchData
      }
    ]);
  };

  const getPromptHeader = () => {
    const user = envVars.USER || 'codak';
    const host = envVars.HOSTNAME || 'localhost';
    const dirDisplay = currentDir === '/home/user' ? '~' : currentDir.replace('/home/user', '~');
    return `-${user}@${host} ${dirDisplay}`;
  };

  const getPromptString = () => {
    return '└─$ ';
  };

  // Autocomplete on Tab key
  const handleTabCompletion = () => {
    const parts = inputVal.split(' ');
    const currentWord = parts[parts.length - 1];

    if (parts.length === 1) {
      const commands = [
        'help', 'clear', 'ls', 'cd', 'pwd', 'cat', 'touch', 'mkdir', 'rm', 'cp', 'mv',
        'wget', 'download', 'nano', 'edit', 'tree', 'grep', 'find', 'wc', 'head', 'tail', 'stat',
        'curl', 'ping', 'dns', 'ip', 'myip', 'speedtest', 'weather',
        'portscan', 'whois', 'cve', 'subdomains', 'hashid', 'sandbox', 'device',
        'headers', 'sec-headers', 'ssl', 'cert', 'passcheck', 'subnet', 'cidr',
        'rot13', 'hex', 'urlencode', 'python', 'py', 'pkg', 'apt', 'pacman',
        'js', 'node', 'run', 'calc', 'hash', 'base64', 'jwt', 'uuid', 'diff',
        'top', 'htop', 'ps', 'kill', 'neofetch', 'uname', 'uptime', 'date', 'whoami',
        'matrix', 'cowsay', 'fortune', 'history', 'menu', 'ai', 'font', 'env', 'export',
        'logo', 'logocolor', 'color',
        // Network, OSINT & Recon
        'intel', 'intelligence', 'osint', 'nmap', 'rdns', 'wayback', 'archive', 'tools', 'who', 'username', 'socials', 'sherlock', 'stalk',
        'github', 'ghrepos', 'ghemail', 'email', 'gravatar', 'phone',
        'geo', 'revgeo', 'country', 'dork', 'search', 'b64', 'url', 'ts', 'fingerprint',
        // Defensive Cyber Security & Web Recon
        'urlscan', 'scanurl', 'urlcheck', 'linkscan', 'info', 'siteinfo', 'webinfo', 'techstack', 'webtech', 'emailsec', 'dmarc', 'robots', 'securitytxt', 'cors', 'httpmethods', 'crack',
        // Top-Tier Bug Bounty Toolkit
        'subtakeover', 'takeover', 'bounty', 'vdp', 'cvss', 'report', 'triage',
        // WhatsApp Privacy & Anti-Doxxing
        'wa-protect', 'wa-doxx', 'wa-rescue', 'wa-check', 'wa', 'whatsapp', 'wa-link',
        // Cyber Security Competition & CTF Arena
        'ctf', 'ctfd', 'strings', 'binwalk', 'lomba', 'cyber-cheat', 'tshark',
        // 15 Cyber Security Tools
        'wireshark', 'metasploit', 'msfconsole', 'burpsuite', 'burp', 'openvas', 'nikto', 'hashcat',
        'sqlmap', 'aircrack-ng', 'aircrack', 'john', 'snort', 'ossec', 'maltego', 'setoolkit', 'autopsy',
        // System & Android ARM
        'battery', 'mount', 'umount', 'df', 'chroot'
      ];
      const matches = commands.filter(c => c.startsWith(currentWord));
      if (matches.length === 1) {
        setInputVal(matches[0] + ' ');
      } else if (matches.length > 1) {
        addLine('output', matches.join('   '));
      }
    } else {
      // Path autocompletion
      const items = vfs.listDirectory(currentDir);
      const names = items.map(i => i.name + (i.type === 'dir' ? '/' : ''));
      const matches = names.filter(n => n.startsWith(currentWord));
      if (matches.length === 1) {
        parts[parts.length - 1] = matches[0];
        setInputVal(parts.join(' '));
      } else if (matches.length > 1) {
        addLine('output', matches.join('   '));
      }
    }
  };

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      handleTabCompletion();
      return;
    }

    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length === 0) return;
      const nextIndex = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIndex);
      setInputVal(history[nextIndex]);
      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex === -1) return;
      if (historyIndex < history.length - 1) {
        const nextIndex = historyIndex + 1;
        setHistoryIndex(nextIndex);
        setInputVal(history[nextIndex]);
      } else {
        setHistoryIndex(-1);
        setInputVal('');
      }
      return;
    }

    // Ctrl+C: Cancel current line
    if (e.ctrlKey && e.key === 'c') {
      e.preventDefault();
      addLine('input', inputVal + '^C', getPromptHeader());
      setInputVal('');
      setHistoryIndex(-1);
      return;
    }

    // Ctrl+L: Clear screen
    if (e.ctrlKey && e.key === 'l') {
      e.preventDefault();
      setLines([]);
      return;
    }

    if (e.key === 'Enter') {
      e.preventDefault();
      executeCurrentCommand();
    }
  };

  const executeCurrentCommand = async () => {
    const rawCmd = inputVal;
    const trimmed = rawCmd.trim();

    // Echo input to terminal
    addLine('input', rawCmd, getPromptHeader());

    setInputVal('');
    setHistoryIndex(-1);

    if (!trimmed) {
      return;
    }

    // Save to history
    setHistory(prev => [...prev, trimmed]);

    setIsProcessing(true);

    try {
      await runCommand(trimmed);
    } catch (err: any) {
      addLine('error', `Error: ${err.message || 'Execution failed'}`);
    } finally {
      setIsProcessing(false);
    }
  };

  // Dispatch commands
  const runCommand = async (commandStr: string) => {
    // Redirection support: command > file or command >> file
    let redirection: { type: '>' | '>>'; targetFile: string } | null = null;
    let actualCommand = commandStr;

    if (commandStr.includes('>>')) {
      const parts = commandStr.split('>>');
      actualCommand = parts[0].trim();
      redirection = { type: '>>', targetFile: parts[1].trim() };
    } else if (commandStr.includes('>')) {
      const parts = commandStr.split('>');
      actualCommand = parts[0].trim();
      redirection = { type: '>', targetFile: parts[1].trim() };
    }

    const args = actualCommand.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
    if (args.length === 0) return;

    // Remove quotes
    let cleanArgs = args.map(a => a.replace(/^["']|["']$/g, ''));
    if (cleanArgs.length > 1 && ['gw', 'gue', 'aku', 'sudo'].includes(cleanArgs[0].toLowerCase())) {
      cleanArgs.shift();
    }
    const mainCmd = cleanArgs[0].toLowerCase();

    let outputResult: string | null = null;

    // --- QUICK MENU HANDLERS ---
    if (mainCmd === '1') {
      await handleNeofetch();
      return;
    }
    if (mainCmd === '2') {
      await handleSpeedtest();
      return;
    }
    if (mainCmd === '3') {
      await handleLs(['-la']);
      return;
    }
    if (mainCmd === '4') {
      setActiveApp('top');
      return;
    }
    if (mainCmd === '5') {
      addLine('output', `Network Tools Available:\n- curl <url>     : Real HTTP fetcher\n- ping <host>    : Real latency measurement\n- dns <host>     : Real DNS lookup (A, MX, etc)\n- ip             : Client public IP & location\n- speedtest      : Download bandwidth test\n- weather <city> : Real ASCII weather report`);
      return;
    }

    // --- MAIN TOOLS DISPATCH ---
    switch (mainCmd) {
      case 'help':
        outputResult = getHelpText();
        break;

      case 'logo':
        addLine('logo', ATRIX_LOGO_ASCII);
        return;

      case 'logocolor':
      case 'color':
        const targetColorArg = mainCmd === 'color' && cleanArgs[1] === 'logo' ? cleanArgs[2] : cleanArgs[1];
        outputResult = handleLogoColor(targetColorArg);
        break;

      case 'menu':
        addLine('logo', ATRIX_LOGO_ASCII);
        addLine('ascii', ATRIX_ASCII);
        break;

      case 'clear':
        setLines([]);
        return;

      // 1. Filesystem Tools
      case 'pwd':
        outputResult = currentDir;
        break;

      case 'ls':
      case 'dir':
        await handleLs(cleanArgs.slice(1));
        return;

      case 'cd':
        handleCd(cleanArgs[1]);
        return;

      case 'cat':
        outputResult = handleCat(cleanArgs.slice(1));
        break;

      case 'touch':
        outputResult = handleTouch(cleanArgs.slice(1));
        break;

      case 'mkdir':
        outputResult = handleMkdir(cleanArgs.slice(1));
        break;

      case 'rm':
        outputResult = handleRm(cleanArgs.slice(1));
        break;

      case 'cp':
        outputResult = handleCp(cleanArgs.slice(1));
        break;

      case 'mv':
        outputResult = handleMv(cleanArgs.slice(1));
        break;

      case 'tree':
        outputResult = handleTree(cleanArgs.slice(1));
        break;

      case 'grep':
        outputResult = handleGrep(cleanArgs.slice(1));
        break;

      case 'find':
        outputResult = handleFind(cleanArgs.slice(1));
        break;

      case 'wc':
        outputResult = handleWc(cleanArgs.slice(1));
        break;

      case 'head':
        outputResult = handleHead(cleanArgs.slice(1));
        break;

      case 'tail':
        outputResult = handleTail(cleanArgs.slice(1));
        break;

      case 'stat':
        outputResult = handleStat(cleanArgs.slice(1));
        break;

      case 'echo':
        outputResult = cleanArgs.slice(1).join(' ');
        break;

      case 'nano':
      case 'edit':
        handleNano(cleanArgs[1]);
        return;

      // 2. Real Network Utilities
      case 'curl':
        await handleCurl(cleanArgs.slice(1));
        return;

      case 'ping':
        await handlePing(cleanArgs[1]);
        return;

      case 'dns':
      case 'nslookup':
      case 'dig':
        await handleDns(cleanArgs.slice(1));
        return;

      case 'ip':
      case 'ifconfig':
        await handleIp(cleanArgs[1]);
        return;

      case 'myip':
        await handleIp();
        return;

      case 'speedtest':
        await handleSpeedtest();
        return;

      case 'weather':
      case 'wttr':
        await handleWeather(cleanArgs.slice(1).join(' '));
        return;

      // 3. Developer & Security Utilities
      case 'js':
      case 'eval':
        outputResult = handleJsEval(cleanArgs.slice(1).join(' '));
        break;

      case 'run':
      case 'node':
        outputResult = handleRunScript(cleanArgs[1]);
        break;

      case 'calc':
        outputResult = handleCalc(cleanArgs.slice(1).join(' '));
        break;

      case 'hash':
        outputResult = await handleHash(cleanArgs.slice(1));
        break;

      case 'base64':
        outputResult = handleBase64(cleanArgs.slice(1));
        break;

      case 'jwt':
        outputResult = handleJwt(cleanArgs[1]);
        break;

      case 'uuid':
        outputResult = generateUUID();
        break;

      case 'diff':
        outputResult = handleDiff(cleanArgs.slice(1));
        break;

      // Defensive Security Audit & Network Analysis
      case 'headers':
      case 'sec-headers':
        await handleHeadersAudit(cleanArgs[1]);
        return;

      case 'ssl':
      case 'cert':
        await handleSslAudit(cleanArgs[1]);
        return;

      case 'passcheck':
        outputResult = handlePassCheck(cleanArgs.slice(1).join(' '));
        break;

      case 'subnet':
      case 'cidr':
        outputResult = handleSubnet(cleanArgs[1]);
        break;

      case 'rot13':
        outputResult = cleanArgs.length > 1 ? rot13(cleanArgs.slice(1).join(' ')) : 'Usage: rot13 <text>';
        break;

      case 'hex':
        outputResult = handleHex(cleanArgs.slice(1));
        break;

      case 'urlencode':
      case 'urldecode':
        outputResult = handleUrlTransform(mainCmd, cleanArgs.slice(1).join(' '));
        break;

      // Direct File Downloader into Virtual Sandbox
      case 'wget':
      case 'download':
        await handleWget(cleanArgs.slice(1));
        return;

      // Defensive Cyber Security & Reconnaissance
      case 'portscan':
      case 'port':
        await handlePortscan(cleanArgs[1]);
        return;

      case 'intel':
      case 'intelligence':
      case 'osint':
        await cyberCmds.handleIntelCommand(cleanArgs, addLine);
        return;

      case 'nmap':
        await cyberCmds.handleNmapCommand(cleanArgs, addLine);
        return;

      case 'rdns':
        await cyberCmds.handleRdnsCommand(cleanArgs, addLine);
        return;

      case 'wayback':
      case 'archive':
        await cyberCmds.handleWaybackCommand(cleanArgs, addLine);
        return;

      case 'tools':
        cyberCmds.handleToolsCommand(cleanArgs, addLine);
        return;

      case 'who':
      case 'username':
        await cyberCmds.handleWhoCommand(cleanArgs, addLine);
        return;

      case 'socials':
        cyberCmds.handleSocialsCommand(cleanArgs, addLine);
        return;

      case 'sherlock':
      case 'stalk':
        await cyberCmds.handleSherlockCommand(cleanArgs, addLine);
        return;

      case 'github':
        await cyberCmds.handleGithubCommand(cleanArgs, addLine);
        return;

      case 'ghrepos':
        await cyberCmds.handleGhReposCommand(cleanArgs, addLine);
        return;

      case 'ghemail':
        await cyberCmds.handleGhEmailCommand(cleanArgs, addLine);
        return;

      case 'email':
        await cyberCmds.handleEmailCommand(cleanArgs, addLine);
        return;

      case 'gravatar':
        await cyberCmds.handleGravatarCommand(cleanArgs, addLine);
        return;

      case 'phone':
        cyberCmds.handlePhoneCommand(cleanArgs, addLine);
        return;

      case 'geo':
        await cyberCmds.handleGeoCommand(cleanArgs, addLine);
        return;

      case 'revgeo':
        await cyberCmds.handleRevGeoCommand(cleanArgs, addLine);
        return;

      case 'country':
        await cyberCmds.handleCountryCommand(cleanArgs, addLine);
        return;

      case 'dork':
        cyberCmds.handleDorkCommand(cleanArgs, addLine);
        return;

      case 'search':
        cyberCmds.handleSearchCommand(cleanArgs, addLine);
        return;

      case 'ts':
        cyberCmds.handleTsCommand(cleanArgs, addLine);
        return;

      case 'info':
      case 'siteinfo':
      case 'webinfo':
        await cyberCmds.handleInfoCommand(cleanArgs, addLine);
        return;

      case 'techstack':
      case 'webtech':
        await cyberCmds.handleTechstackCommand(cleanArgs, addLine);
        return;

      case 'emailsec':
      case 'dmarc':
        await cyberCmds.handleEmailSecCommand(cleanArgs, addLine);
        return;

      case 'robots':
      case 'securitytxt':
        await cyberCmds.handleCrawlersCommand(cleanArgs, addLine);
        return;

      case 'cors':
      case 'httpmethods':
        await cyberCmds.handleCorsCommand(cleanArgs, addLine);
        return;

      // Top-Tier Bug Bounty Toolkit
      case 'subtakeover':
      case 'takeover':
        await cyberCmds.handleSubtakeoverCommand(cleanArgs, addLine);
        return;

      case 'bounty':
      case 'vdp':
        await cyberCmds.handleBountyCommand(cleanArgs, addLine);
        return;

      case 'cvss':
        cyberCmds.handleCvssCommand(cleanArgs, addLine);
        return;

      case 'report':
      case 'triage':
        cyberCmds.handleReportCommand(cleanArgs, addLine);
        return;

      // WhatsApp Security & Anti-Doxxing Suite
      case 'wa-protect':
      case 'wa-doxx':
      case 'wa-rescue':
      case 'wa-aman':
        cyberCmds.handleWaProtectCommand(cleanArgs, addLine);
        return;

      case 'wa-check':
      case 'wa':
      case 'whatsapp':
        cyberCmds.handleWaCheckCommand(cleanArgs, addLine);
        return;

      case 'wa-link':
      case 'walink':
        cyberCmds.handleWaLinkCommand(cleanArgs, addLine);
        return;

      case 'crack':
        await cyberCmds.handleCrackCommand(cleanArgs, addLine);
        return;

      case 'b64':
        outputResult = handleBase64(cleanArgs.slice(1));
        break;

      case 'url':
        outputResult = handleUrlTransform(cleanArgs[1] === 'dec' ? 'urldecode' : 'urlencode', cleanArgs.slice(2).join(' '));
        break;

      case 'fingerprint':
        cyberCmds.handleFingerprintCommand(addLine);
        return;

      case 'urlscan':
      case 'scanurl':
      case 'urlcheck':
      case 'linkscan':
        await cyberCmds.handleUrlScanCommand(cleanArgs, addLine);
        return;

      // 15 Cyber Security Tools & CTF Competition Arena
      case 'wireshark':
      case 'tshark':
        cyberCmds.handleWiresharkCommand(cleanArgs, addLine);
        return;

      case 'ctf':
      case 'ctfd':
        cyberCmds.handleCtfCommand(cleanArgs, addLine);
        return;

      case 'strings':
        cyberCmds.handleStringsCommand(cleanArgs, addLine);
        return;

      case 'binwalk':
        cyberCmds.handleBinwalkCommand(cleanArgs, addLine);
        return;

      case 'lomba':
      case 'cyber-cheat':
      case 'ctf-guide':
        cyberCmds.handleLombaCommand(cleanArgs, addLine);
        return;

      case 'metasploit':
      case 'msfconsole':
        cyberCmds.handleMetasploitCommand(cleanArgs, addLine);
        return;

      case 'burpsuite':
      case 'burp':
        cyberCmds.handleBurpCommand(cleanArgs, addLine);
        return;

      case 'openvas':
        await cyberCmds.handleOpenVASCommand(cleanArgs, addLine);
        return;

      case 'nikto':
        cyberCmds.handleNiktoCommand(cleanArgs, addLine);
        return;

      case 'hashcat':
        await cyberCmds.handleHashcatCommand(cleanArgs, addLine);
        return;

      case 'sqlmap':
        cyberCmds.handleSqlmapCommand(cleanArgs, addLine);
        return;

      case 'aircrack-ng':
      case 'aircrack':
        cyberCmds.handleAircrackCommand(cleanArgs, addLine);
        return;

      case 'john':
      case 'john-the-ripper':
        await cyberCmds.handleJohnCommand(cleanArgs, addLine);
        return;

      case 'snort':
        cyberCmds.handleSnortCommand(cleanArgs, addLine);
        return;

      case 'ossec':
        cyberCmds.handleOssecCommand(cleanArgs, addLine);
        return;

      case 'maltego':
        cyberCmds.handleMaltegoCommand(cleanArgs, addLine);
        return;

      case 'setoolkit':
      case 'set':
        cyberCmds.handleSetoolkitCommand(cleanArgs, addLine);
        return;

      case 'autopsy':
        cyberCmds.handleAutopsyCommand(cleanArgs, addLine);
        return;

      // Android ARM & System Commands
      case 'battery':
        await cyberCmds.handleBatteryCommand(addLine);
        return;

      case 'mount':
        cyberCmds.handleMountCommand(addLine);
        return;

      case 'umount':
        outputResult = cleanArgs[1] ? `Unmounted ${cleanArgs[1]}` : 'Usage: umount <mountpoint>';
        break;

      case 'df':
        cyberCmds.handleDfCommand(addLine);
        return;

      case 'chroot':
        cyberCmds.handleChrootCommand(cleanArgs, addLine);
        return;

      case 'whois':
        await handleWhois(cleanArgs[1]);
        return;

      case 'subdomains':
      case 'subdomain':
      case 'subfinder':
        await handleSubdomains(cleanArgs[1]);
        return;

      case 'cve':
        await handleCve(cleanArgs.slice(1).join(' '));
        return;

      case 'hashid':
        outputResult = handleHashId(cleanArgs[1]);
        break;

      // Sandbox & Device Isolation Status
      case 'sandbox':
      case 'device':
      case 'airgap':
        outputResult = handleSandboxStatus();
        break;

      // Python Environment & Runner
      case 'python':
      case 'py':
      case 'python3':
        outputResult = handlePython(cleanArgs.slice(1));
        break;

      // Virtual Package Manager
      case 'pkg':
      case 'apt':
      case 'pacman':
        outputResult = handlePkg(cleanArgs.slice(1));
        break;

      // 4. System & Process Utilities
      case 'top':
      case 'htop':
        setActiveApp('top');
        return;

      case 'ps':
        outputResult = `  PID TTY          TIME CMD
    1 ?        00:00:01 systemd
   42 ?        00:01:12 atrix-core
  108 ?        00:00:00 vfs-daemon
  219 ?        00:00:05 net-service
  912 pts/0    00:00:00 zsh
 1337 pts/0    00:00:00 ps`;
        break;

      case 'kill':
        outputResult = cleanArgs[1] ? `Process ${cleanArgs[1]} sent signal SIGTERM` : 'Usage: kill <pid>';
        break;

      case 'neofetch':
      case 'uname':
        await handleNeofetch();
        return;

      case 'uptime':
        const sec = Math.floor((Date.now() - sessionStartTime.current) / 1000);
        const mins = Math.floor(sec / 60);
        outputResult = `up ${mins} min(s), ${sec % 60} sec(s), 1 user, load average: 0.12, 0.08, 0.05`;
        break;

      case 'date':
        outputResult = new Date().toString();
        break;

      case 'whoami':
        outputResult = envVars.USER || 'user';
        break;

      case 'hostname':
        outputResult = 'atrix-workstation';
        break;

      case 'env':
        outputResult = Object.entries(envVars).map(([k, v]) => `${k}=${v}`).join('\n');
        break;

      case 'export':
        outputResult = handleExport(cleanArgs.slice(1).join(' '));
        break;

      case 'font':
        const newSize = parseInt(cleanArgs[1]);
        if (newSize >= 10 && newSize <= 24) {
          setFontSize(newSize);
          outputResult = `Terminal font size set to ${newSize}px`;
        } else {
          outputResult = 'Usage: font <size 10-24>';
        }
        break;

      case 'history':
        outputResult = history.map((cmd, i) => ` ${i + 1}  ${cmd}`).join('\n');
        break;

      case 'matrix':
        setActiveApp('matrix');
        return;

      case 'cowsay':
        outputResult = handleCowsay(cleanArgs.slice(1).join(' ') || 'ATRIX OS is working!');
        break;

      case 'fortune':
        outputResult = getFortune();
        break;

      case 'ai':
      case 'ask':
        await handleAi(cleanArgs.slice(1).join(' '));
        return;

      default:
        addLine('error', `atrix: ${mainCmd}: command not found. Type 'help' for available tools.`);
        return;
    }

    // Handle output or redirection
    if (outputResult !== null) {
      if (redirection) {
        const destPath = vfs.normalizePath(redirection.targetFile, currentDir);
        vfs.writeFile(destPath, outputResult + '\n', redirection.type === '>>');
        addLine('output', `[ Written to ${redirection.targetFile} ]`);
      } else {
        addLine('output', outputResult);
      }
    }
  };

  // --- IMPLEMENTATIONS OF COMMANDS ---

  const handleLs = async (args: string[]) => {
    let showAll = false;
    let longFormat = false;
    let targetPath = currentDir;

    for (const arg of args) {
      if (arg.startsWith('-')) {
        if (arg.includes('a')) showAll = true;
        if (arg.includes('l')) longFormat = true;
      } else {
        targetPath = vfs.normalizePath(arg, currentDir);
      }
    }

    const items = vfs.listDirectory(targetPath);
    if (!longFormat) {
      const displayNames = items
        .filter(i => showAll || !i.name.startsWith('.'))
        .map(i => i.type === 'dir' ? `${i.name}/` : i.name);
      addLine('output', displayNames.length ? displayNames.join('   ') : '');
    } else {
      const rows = items
        .filter(i => showAll || !i.name.startsWith('.'))
        .map(i => {
          const size = (i.size || (i.type === 'dir' ? 4096 : (i.content?.length || 0))).toString().padStart(6);
          const date = new Date(i.modified).toLocaleDateString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
          const name = i.type === 'dir' ? `${i.name}/` : i.name;
          return `${i.permissions || (i.type === 'dir' ? 'drwxr-xr-x' : '-rw-r--r--')}  1 user user ${size} ${date} ${name}`;
        });
      addLine('output', `total ${rows.length}\n` + rows.join('\n'));
    }
  };

  const handleCd = (target?: string) => {
    if (!target || target === '~') {
      setCurrentDir('/home/user');
      return;
    }
    const resolved = vfs.normalizePath(target, currentDir);
    const item = vfs.getItem(resolved);
    if (!item) {
      addLine('error', `cd: no such file or directory: ${target}`);
      return;
    }
    if (item.type !== 'dir') {
      addLine('error', `cd: not a directory: ${target}`);
      return;
    }
    setCurrentDir(resolved);
  };

  const handleCat = (args: string[]): string => {
    if (args.length === 0) return 'Usage: cat <filename>';
    const outputs: string[] = [];
    for (const file of args) {
      const fullPath = vfs.normalizePath(file, currentDir);
      const item = vfs.getItem(fullPath);
      if (!item) {
        return `cat: ${file}: No such file or directory`;
      }
      if (item.type === 'dir') {
        return `cat: ${file}: Is a directory`;
      }
      outputs.push(item.content || '');
    }
    return outputs.join('\n');
  };

  const handleTouch = (args: string[]): string => {
    if (args.length === 0) return 'Usage: touch <filename>';
    for (const file of args) {
      const fullPath = vfs.normalizePath(file, currentDir);
      vfs.createFile(fullPath, '');
    }
    return '';
  };

  const handleMkdir = (args: string[]): string => {
    if (args.length === 0) return 'Usage: mkdir [-p] <directory>';
    const dirs = args.filter(a => a !== '-p');
    for (const dir of dirs) {
      const fullPath = vfs.normalizePath(dir, currentDir);
      const success = vfs.createDirectory(fullPath);
      if (!success) {
        return `mkdir: cannot create directory '${dir}': File exists or invalid path`;
      }
    }
    return '';
  };

  const handleRm = (args: string[]): string => {
    if (args.length === 0) return 'Usage: rm [-r] <file/dir>';
    const isRecursive = args.includes('-r') || args.includes('-rf');
    const targets = args.filter(a => !a.startsWith('-'));
    for (const t of targets) {
      const fullPath = vfs.normalizePath(t, currentDir);
      const success = vfs.deleteItem(fullPath, isRecursive);
      if (!success) {
        return `rm: cannot remove '${t}': Directory not empty or does not exist (use -r)`;
      }
    }
    return '';
  };

  const handleCp = (args: string[]): string => {
    if (args.length < 2) return 'Usage: cp <source> <destination>';
    const src = vfs.normalizePath(args[0], currentDir);
    const dest = vfs.normalizePath(args[1], currentDir);
    const success = vfs.copyItem(src, dest);
    return success ? '' : `cp: failed to copy '${args[0]}' to '${args[1]}'`;
  };

  const handleMv = (args: string[]): string => {
    if (args.length < 2) return 'Usage: mv <source> <destination>';
    const src = vfs.normalizePath(args[0], currentDir);
    const dest = vfs.normalizePath(args[1], currentDir);
    const success = vfs.moveItem(src, dest);
    return success ? '' : `mv: failed to move '${args[0]}' to '${args[1]}'`;
  };

  const handleTree = (args: string[]): string => {
    const target = args[0] ? vfs.normalizePath(args[0], currentDir) : currentDir;
    const treeLines = vfs.renderTree(target);
    return treeLines.join('\n');
  };

  const handleGrep = (args: string[]): string => {
    if (args.length < 2) return 'Usage: grep <pattern> <file>';
    const pattern = args[0];
    const file = args[1];
    const fullPath = vfs.normalizePath(file, currentDir);
    const item = vfs.getItem(fullPath);
    if (!item || item.type !== 'file') return `grep: ${file}: No such file`;

    const regex = new RegExp(pattern, 'i');
    const matches = (item.content || '').split('\n').filter(l => regex.test(l));
    return matches.length ? matches.join('\n') : 'No match found.';
  };

  const handleFind = (args: string[]): string => {
    if (args.length === 0) return 'Usage: find <name_substring>';
    const query = args[0].toLowerCase();
    const results: string[] = [];

    const searchDir = (dirPath: string) => {
      const items = vfs.listDirectory(dirPath);
      for (const item of items) {
        const itemPath = `${dirPath === '/' ? '' : dirPath}/${item.name}`;
        if (item.name.toLowerCase().includes(query)) {
          results.push(itemPath);
        }
        if (item.type === 'dir') {
          searchDir(itemPath);
        }
      }
    };

    searchDir('/');
    return results.length ? results.join('\n') : `No files found matching '${query}'`;
  };

  const handleWc = (args: string[]): string => {
    if (args.length === 0) return 'Usage: wc <file>';
    const fullPath = vfs.normalizePath(args[0], currentDir);
    const item = vfs.getItem(fullPath);
    if (!item || item.type !== 'file') return `wc: ${args[0]}: No such file`;
    const text = item.content || '';
    const lines = text.split('\n').length;
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    const bytes = text.length;
    return ` ${lines}  ${words} ${bytes} ${args[0]}`;
  };

  const handleHead = (args: string[]): string => {
    let count = 10;
    let filename = args[0];
    if (args[0] === '-n' && args[1]) {
      count = parseInt(args[1]) || 10;
      filename = args[2];
    }
    if (!filename) return 'Usage: head [-n lines] <file>';
    const fullPath = vfs.normalizePath(filename, currentDir);
    const item = vfs.getItem(fullPath);
    if (!item || item.type !== 'file') return `head: ${filename}: No such file`;
    return (item.content || '').split('\n').slice(0, count).join('\n');
  };

  const handleTail = (args: string[]): string => {
    let count = 10;
    let filename = args[0];
    if (args[0] === '-n' && args[1]) {
      count = parseInt(args[1]) || 10;
      filename = args[2];
    }
    if (!filename) return 'Usage: tail [-n lines] <file>';
    const fullPath = vfs.normalizePath(filename, currentDir);
    const item = vfs.getItem(fullPath);
    if (!item || item.type !== 'file') return `tail: ${filename}: No such file`;
    const lines = (item.content || '').split('\n');
    return lines.slice(Math.max(0, lines.length - count)).join('\n');
  };

  const handleStat = (args: string[]): string => {
    if (args.length === 0) return 'Usage: stat <file>';
    const fullPath = vfs.normalizePath(args[0], currentDir);
    const item = vfs.getItem(fullPath);
    if (!item) return `stat: cannot stat '${args[0]}': No such file or directory`;
    return `  File: ${item.name}
  Size: ${item.size || item.content?.length || 4096}  Blocks: 8  IO Block: 4096  ${item.type === 'dir' ? 'directory' : 'regular file'}
Access: (${item.permissions || (item.type === 'dir' ? '0755/drwxr-xr-x' : '0644/-rw-r--r--')})  Uid: ( 1000/    user)   Gid: ( 1000/    user)
Modify: ${item.modified}`;
  };

  const handleNano = (filename?: string) => {
    if (!filename) {
      addLine('error', 'Usage: nano <filename>');
      return;
    }
    const fullPath = vfs.normalizePath(filename, currentDir);
    const existing = vfs.getItem(fullPath);
    let initialText = '';
    if (existing) {
      if (existing.type === 'dir') {
        addLine('error', `nano: ${filename} is a directory`);
        return;
      }
      initialText = existing.content || '';
    }
    setNanoTargetFile(fullPath);
    setNanoInitialContent(initialText);
    setActiveApp('nano');
  };

  // Real Network Handlers
  const handleCurl = async (args: string[]) => {
    if (args.length === 0) {
      addLine('error', 'Usage: curl [-I] [-X METHOD] [-d "DATA"] <url>');
      return;
    }

    let url = '';
    let method = 'GET';
    let headersOnly = false;
    let postData: any = null;

    for (let i = 0; i < args.length; i++) {
      if (args[i] === '-I' || args[i] === '--head') {
        headersOnly = true;
      } else if (args[i] === '-X' && args[i + 1]) {
        method = args[i + 1].toUpperCase();
        i++;
      } else if (args[i] === '-d' && args[i + 1]) {
        postData = args[i + 1];
        if (method === 'GET') method = 'POST';
        i++;
      } else if (!args[i].startsWith('-')) {
        url = args[i];
      }
    }

    if (!url) {
      addLine('error', 'curl: no URL specified');
      return;
    }

    addLine('output', `* Connecting to ${url}...`);

    try {
      const res = await fetch('/api/curl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, method, body: postData })
      });

      const result = await res.json();
      if (!res.ok) {
        addLine('error', `curl: (52) ${result.error || 'Request failed'} (${result.timeMs || 0}ms)`);
        return;
      }

      if (headersOnly) {
        let headersFormatted = `HTTP/1.1 ${result.status} ${result.statusText}\n`;
        for (const [k, v] of Object.entries(result.headers || {})) {
          headersFormatted += `${k}: ${v}\n`;
        }
        addLine('output', headersFormatted);
      } else {
        const bodyStr = result.isJson
          ? JSON.stringify(result.data, null, 2)
          : String(result.data);
        addLine('output', bodyStr);
        addLine('system', `* Received ${result.size} bytes in ${result.timeMs}ms (HTTP ${result.status})`);
      }
    } catch (err: any) {
      addLine('error', `curl: (7) Failed to connect: ${err.message}`);
    }
  };

  const handlePing = async (host?: string) => {
    if (!host) {
      addLine('error', 'Usage: ping <host>');
      return;
    }
    addLine('output', `PING ${host} 56(84) bytes of data.`);

    try {
      const res = await fetch('/api/ping', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host })
      });
      const data = await res.json();

      if (!res.ok) {
        addLine('error', data.error || `ping: cannot resolve ${host}: Unknown host`);
        return;
      }

      data.samples.forEach((ms: number, idx: number) => {
        if (ms >= 0) {
          addLine('output', `64 bytes from ${data.host}: icmp_seq=${idx + 1} ttl=57 time=${ms} ms`);
        } else {
          addLine('output', `Request timeout for icmp_seq ${idx + 1}`);
        }
      });

      addLine('output', `--- ${data.host} ping statistics ---
${data.packetsSent} packets transmitted, ${data.packetsReceived} received, ${data.packetLoss}% packet loss
rtt min/avg/max = ${data.min}/${data.avg}/${data.max} ms`);
    } catch (err: any) {
      addLine('error', `ping: sendto: Network is unreachable (${err.message})`);
    }
  };

  const handleDns = async (args: string[]) => {
    if (args.length === 0) {
      addLine('error', 'Usage: dns <host> [A|AAAA|MX|TXT|NS|CNAME]');
      return;
    }
    const host = args[0];
    const type = (args[1] || 'A').toUpperCase();

    addLine('output', `; <<>> ATRIX DiG 9.18 <<>> ${type} ${host}`);

    try {
      const res = await fetch('/api/dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, type })
      });
      const data = await res.json();

      if (!res.ok) {
        addLine('error', `;; connection timed out; no servers could be reached (${data.error})`);
        return;
      }

      let recordLines: string[] = [];
      if (Array.isArray(data.records)) {
        recordLines = data.records.map((r: any) => {
          if (typeof r === 'object') {
            return `${data.host}.\t\t300\tIN\t${data.type}\t${JSON.stringify(r)}`;
          }
          return `${data.host}.\t\t300\tIN\t${data.type}\t${r}`;
        });
      }

      addLine('output', `;; QUESTION SECTION:\n;${data.host}.\t\t\tIN\t${data.type}\n\n;; ANSWER SECTION:\n${recordLines.join('\n') || '; No records found'}`);
    } catch (err: any) {
      addLine('error', `dns resolution error: ${err.message}`);
    }
  };

  const handleIp = async (target?: string) => {
    addLine('output', target ? `Looking up IP & Geolocation intel for '${target}'...` : 'Detecting network configuration...');
    try {
      const url = target ? `/api/ip?target=${encodeURIComponent(target)}` : '/api/ip';
      const res = await fetch(url);
      const data = await res.json();
      if (!res.ok) {
        addLine('error', data.error || 'Failed to obtain IP details');
        return;
      }
      if (data.isRemoteTarget) {
        let out = `IP Intelligence & Geolocation for ${data.ip} (${data.target || ''})
──────────────────────────────────────────────────────────
Country   : ${data.country} (${data.country_code})
City/Reg  : ${data.city}, ${data.region}
ASN / ISP : ${data.asn || 'N/A'} - ${data.org}
Timezone  : ${data.timezone}
Coords    : ${data.latitude && data.longitude ? `${data.latitude}, ${data.longitude}` : 'N/A'}`;
        if (data.reverseDns && data.reverseDns.length > 0) {
          out += `\nHostnames : ${data.reverseDns.join(', ')}`;
        }
        addLine('output', out);
      } else {
        addLine('output', `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet ${data.ip}  netmask 255.255.255.0
        Location : ${data.city}, ${data.region}, ${data.country} (${data.country_code})
        ISP/Org  : ${data.org} (ASN: ${data.asn || 'N/A'})
        Timezone : ${data.timezone}
        UserAgent: ${data.userAgent}`);
      }
    } catch (err: any) {
      addLine('error', `Failed to obtain IP details: ${err.message}`);
    }
  };

  const handleSpeedtest = async () => {
    addLine('output', 'Testing network latency and download throughput...');
    try {
      const t0 = performance.now();
      const testChunkMb = 2;
      const res = await fetch(`/api/speedtest/chunk?mb=${testChunkMb}&_t=${Date.now()}`);
      if (!res.ok) throw new Error('Speedtest endpoint unavailable');
      const blob = await res.blob();
      const durationSec = (performance.now() - t0) / 1000;
      const sizeBits = blob.size * 8;
      const mbps = ((sizeBits / durationSec) / (1024 * 1024)).toFixed(2);
      const pingMs = Math.round(durationSec * 100);

      addLine('ascii', `==========================================
        ATRIX SPEEDTEST RESULTS           
==========================================
 Ping Latency  : ${pingMs} ms
 Download Speed: ${mbps} Mbps
 Transferred   : ${(blob.size / (1024 * 1024)).toFixed(2)} MB
 Status        : 100% SUCCESS
==========================================`);
    } catch (err: any) {
      addLine('error', `Speedtest error: ${err.message}`);
    }
  };

  const handleWeather = async (city: string) => {
    addLine('output', `Fetching weather forecast${city ? ' for ' + city : ''}...`);
    try {
      const res = await fetch(`/api/weather?city=${encodeURIComponent(city)}`);
      const text = await res.text();
      addLine('ascii', text);
    } catch (err: any) {
      addLine('error', `Weather check failed: ${err.message}`);
    }
  };

  // Developer & Security Handlers
  const handleJsEval = (code: string): string => {
    if (!code) return 'Usage: js <expression>';
    try {
      // Sandboxed execution
      const fn = new Function(`"use strict"; return (${code});`);
      const res = fn();
      return typeof res === 'object' ? JSON.stringify(res, null, 2) : String(res);
    } catch (err: any) {
      return `EvalError: ${err.message}`;
    }
  };

  const handleRunScript = (filename?: string): string => {
    if (!filename) return 'Usage: run <filename.js>';
    const fullPath = vfs.normalizePath(filename, currentDir);
    const item = vfs.getItem(fullPath);
    if (!item || item.type !== 'file') return `run: ${filename}: No such file`;

    const logs: string[] = [];
    const customConsole = {
      log: (...args: any[]) => logs.push(args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ')),
      error: (...args: any[]) => logs.push('[ERROR] ' + args.join(' ')),
      warn: (...args: any[]) => logs.push('[WARN] ' + args.join(' '))
    };

    try {
      const fn = new Function('console', `"use strict"; ${item.content || ''}`);
      fn(customConsole);
      return logs.length ? logs.join('\n') : '[Script finished with no output]';
    } catch (err: any) {
      return `RuntimeError in ${filename}: ${err.message}\n${logs.join('\n')}`;
    }
  };

  const handleCalc = (expr: string): string => {
    if (!expr) return 'Usage: calc <expression> (e.g. "calc 2^8 + sqrt(16)", "calc 100 c to f", "calc 50 km to miles")';
    try {
      return evaluateCalc(expr);
    } catch (err: any) {
      return `calc error: ${err.message}`;
    }
  };

  const handleHash = async (args: string[]): Promise<string> => {
    if (args.length < 2) return 'Usage: hash <sha256|sha512|sha1|md5> <string>';
    const algoRaw = args[0].toLowerCase();
    const text = args.slice(1).join(' ');
    let algo: 'SHA-256' | 'SHA-512' | 'SHA-1' | 'MD5' = 'SHA-256';

    if (algoRaw === 'sha512') algo = 'SHA-512';
    else if (algoRaw === 'sha1') algo = 'SHA-1';
    else if (algoRaw === 'md5') algo = 'MD5';
    else algo = 'SHA-256';

    const hashed = await computeHash(algo, text);
    return `${algo}: ${hashed}`;
  };

  const handleBase64 = (args: string[]): string => {
    if (args.length < 2) return 'Usage: base64 <encode|decode> <string>';
    const mode = args[0].toLowerCase();
    const str = args.slice(1).join(' ');
    if (mode === 'encode' || mode === '-e') {
      return base64Encode(str);
    }
    if (mode === 'decode' || mode === '-d') {
      return base64Decode(str);
    }
    return 'Invalid mode. Use "encode" or "decode".';
  };

  const handleJwt = (token?: string): string => {
    if (!token) return 'Usage: jwt <jwt_token>';
    try {
      const parsed = parseJwt(token);
      return `HEADER:\n${JSON.stringify(parsed.header, null, 2)}\n\nPAYLOAD:\n${JSON.stringify(parsed.payload, null, 2)}\n\nEXPIRED: ${parsed.isExpired ? 'YES' : 'NO'}${parsed.expDate ? ` (Expires at: ${parsed.expDate})` : ''}`;
    } catch (err: any) {
      return `JWT decode error: ${err.message}`;
    }
  };

  const handleDiff = (args: string[]): string => {
    if (args.length < 2) return 'Usage: diff <file1> <file2>';
    const f1 = vfs.getItem(vfs.normalizePath(args[0], currentDir));
    const f2 = vfs.getItem(vfs.normalizePath(args[1], currentDir));
    if (!f1 || f1.type !== 'file') return `diff: ${args[0]}: No such file`;
    if (!f2 || f2.type !== 'file') return `diff: ${args[1]}: No such file`;
    const diffs = lineDiff(f1.content || '', f2.content || '');
    return diffs.join('\n');
  };

  // Defensive Security & Audit Handlers
  const handleHeadersAudit = async (targetUrl?: string) => {
    if (!targetUrl) {
      addLine('error', 'Usage: headers <url> (contoh: headers github.com atau headers google.com)');
      return;
    }
    addLine('output', `* Auditing defensive HTTP security headers for ${targetUrl}...`);
    try {
      const res = await fetch('/api/security/headers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });
      const data = await res.json();
      if (!res.ok) {
        addLine('error', `Audit failed: ${data.error || 'Server error'}`);
        return;
      }

      let checkLines = '';
      data.checks.forEach((c: any) => {
        const mark = c.present ? '[ PASS ]' : '[ FAIL ]';
        checkLines += `${mark} ${c.name}\n         Status: ${c.present ? c.value : 'MISSING (Vulnerable)'}\n         Purpose: ${c.desc}\n`;
      });

      addLine('ascii', `===========================================================
          ATRIX HTTP SECURITY HEADERS AUDIT REPORT         
===========================================================
 Target URL    : ${data.url}
 Server Header : ${data.server}
 Security Grade: ${data.grade} (${data.score}/100)
-----------------------------------------------------------
${checkLines}===========================================================`);
    } catch (err: any) {
      addLine('error', `Headers check error: ${err.message}`);
    }
  };

  const handleSslAudit = async (host?: string) => {
    if (!host) {
      addLine('error', 'Usage: ssl <host> (contoh: ssl google.com atau ssl github.com)');
      return;
    }
    addLine('output', `* Performing TLS handshake and inspecting certificate for ${host}...`);
    try {
      const res = await fetch('/api/security/ssl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host })
      });
      const data = await res.json();
      if (!res.ok) {
        addLine('error', `SSL audit error: ${data.error || 'Failed to inspect TLS certificate'}`);
        return;
      }

      const status = data.isExpired
        ? 'EXPIRED (CRITICAL)'
        : data.daysRemaining < 30
        ? `EXPIRING SOON (${data.daysRemaining} days left)`
        : `VALID (${data.daysRemaining} days remaining)`;

      addLine('ascii', `===========================================================
          ATRIX SSL / TLS CERTIFICATE AUDIT REPORT         
===========================================================
 Host          : ${data.host}
 Status        : ${status}
 Protocol / Cipher: ${data.protocol} (${data.cipher})
 Common Name   : ${data.subject.CN || 'N/A'}
 Organization  : ${data.subject.O || 'N/A'}
 Issuer        : ${data.issuer.O || data.issuer.CN || 'Unknown CA'}
 Valid From    : ${data.validFrom}
 Valid Until   : ${data.validTo}
 SHA-256 Fingerprint:
   ${data.fingerprint256}
 Subject Alt Names (SAN):
   ${data.subjectAltNames}
===========================================================`);
    } catch (err: any) {
      addLine('error', `SSL Audit error: ${err.message}`);
    }
  };

  const handlePassCheck = (password?: string): string => {
    if (!password) {
      return 'Usage: passcheck <password_to_analyze>\n(Evaluates entropy in bits and offline brute-force crack time estimation)';
    }
    const res = analyzePassword(password);
    const recs = res.recommendations.length ? res.recommendations.map(r => ` - ${r}`).join('\n') : ' - Password follows all standard complexity guidelines.';
    return `===========================================================
          ATRIX PASSWORD STRENGTH & ENTROPY AUDITOR        
===========================================================
 Length        : ${res.length} characters
 Entropy       : ${res.entropy} bits
 Overall Rating: ${res.rating}
 Estimated Crack Time (100B guesses/sec offline attack):
   ${res.crackTime}
 Character Variety:
   - Lowercase [a-z] : ${res.characterSet.hasLower ? 'YES' : 'NO'}
   - Uppercase [A-Z] : ${res.characterSet.hasUpper ? 'YES' : 'NO'}
   - Digits [0-9]    : ${res.characterSet.hasDigits ? 'YES' : 'NO'}
   - Symbols [!@#$]  : ${res.characterSet.hasSymbols ? 'YES' : 'NO'}
 Defensive Recommendations:
${recs}
===========================================================`;
  };

  const handleSubnet = (cidr?: string): string => {
    if (!cidr) {
      return 'Usage: subnet <ip/cidr> (contoh: subnet 192.168.1.0/24 atau subnet 10.0.0.0/16)';
    }
    try {
      const res = calculateSubnet(cidr);
      return `===========================================================
             ATRIX IPv4 CIDR & SUBNET CALCULATOR           
===========================================================
 CIDR Notation : ${res.cidr}
 Network IP    : ${res.network}
 Subnet Netmask: ${res.netmask}
 Wildcard Mask : ${res.wildcard}
 Broadcast IP  : ${res.broadcast}
 Usable Range  : ${res.firstUsable}  -->  ${res.lastUsable}
 Total Hosts   : ${res.totalHosts.toLocaleString()}
 Usable Hosts  : ${res.usableHosts.toLocaleString()}
===========================================================`;
    } catch (err: any) {
      return `Subnet error: ${err.message}`;
    }
  };

  const handleHex = (args: string[]): string => {
    if (args.length < 2) return 'Usage: hex <encode|decode> <text_or_hex_string>';
    const mode = args[0].toLowerCase();
    const str = args.slice(1).join(' ');
    try {
      if (mode === 'encode' || mode === '-e') return hexEncode(str);
      if (mode === 'decode' || mode === '-d') return hexDecode(str);
      return 'Invalid mode. Use "encode" or "decode".';
    } catch (err: any) {
      return `Hex error: ${err.message}`;
    }
  };

  const handleUrlTransform = (mode: string, str: string): string => {
    if (!str) return `Usage: ${mode} <string>`;
    try {
      return mode === 'urlencode' ? urlEncode(str) : urlDecode(str);
    } catch (err: any) {
      return `URL transform error: ${err.message}`;
    }
  };

  // Wget / Direct Web File Downloader
  const handleWget = async (args: string[]) => {
    if (args.length === 0) {
      addLine('error', 'Usage: wget <url> [destination_filename]\nContoh: wget https://example.com/data.json\n        wget https://raw.githubusercontent.com/octocat/Hello-World/master/README script.txt');
      return;
    }

    const targetUrl = args[0];
    const customFilename = args[1];

    addLine('output', `--${new Date().toLocaleTimeString()}--  ${targetUrl}`);
    addLine('output', 'Connecting to remote host... connected.');
    addLine('output', 'HTTP request sent, awaiting response... 200 OK');

    try {
      const res = await fetch('/api/wget', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, filename: customFilename })
      });

      const data = await res.json();
      if (!res.ok) {
        addLine('error', `wget error: ${data.error || 'Failed to download file'}`);
        return;
      }

      const destPath = vfs.normalizePath(data.filename, currentDir);
      vfs.createFileRecursive(destPath, data.content);
      vfs.saveFS();

      const kbytes = (data.size / 1024).toFixed(1);
      addLine('output', `Length: ${data.size} (${kbytes}K) [${data.contentType}]
Saving to: '${data.filename}'

${data.filename.padEnd(20)} 100%[===================>]   ${kbytes}K  --.-KB/s    in ${data.timeMs}ms

${new Date().toLocaleTimeString()} - '${data.filename}' saved [${data.size}/${data.size}]`);

      addLine('system', `[ SUCCESS: File '${data.filename}' saved exclusively in Virtual Sandbox VFS. 0 bytes on your physical device. ]`);
    } catch (err: any) {
      addLine('error', `wget: download failed: ${err.message}`);
    }
  };

  // Nmap-Style TCP Port Scanner
  const handlePortscan = async (host?: string) => {
    if (!host) {
      addLine('error', 'Usage: portscan <host> (contoh: portscan google.com atau portscan scanme.nmap.org)');
      return;
    }

    addLine('output', `Starting ATRIX Port Scanner at ${new Date().toLocaleTimeString()}
Scanning target: ${host} (ports: 21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080)...`);

    try {
      const res = await fetch('/api/security/portscan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host })
      });

      const data = await res.json();
      if (!res.ok) {
        addLine('error', `portscan: ${data.error || 'Port scan failed'}`);
        return;
      }

      let portRows = 'PORT      STATE       SERVICE     LATENCY\n';
      data.results.forEach((r: any) => {
        const portStr = `${r.port}/tcp`.padEnd(10);
        const stateStr = r.status.toUpperCase().padEnd(12);
        const servStr = r.service.padEnd(12);
        portRows += `${portStr}${stateStr}${servStr}${r.timeMs}ms\n`;
      });

      addLine('ascii', `===========================================================
             ATRIX PORT SCANNER REPORT (DEFENSIVE)         
===========================================================
 Target Host   : ${data.host}
 Ports Scanned : ${data.portsScanned}
 Open Ports    : ${data.openPorts.length > 0 ? data.openPorts.map((p: any) => p.port + '/' + p.service).join(', ') : 'None open (filtered/firewalled)'}
 Duration      : ${data.timeMs} ms
-----------------------------------------------------------
${portRows}===========================================================`);
    } catch (err: any) {
      addLine('error', `portscan error: ${err.message}`);
    }
  };

  // WHOIS Registry Lookup
  const handleWhois = async (domain?: string) => {
    if (!domain) {
      addLine('error', 'Usage: whois <domain> (contoh: whois github.com atau whois google.com)');
      return;
    }

    addLine('output', `[Querying IANA / Registrar WHOIS database for ${domain}...]`);

    try {
      const res = await fetch('/api/security/whois', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });

      const data = await res.json();
      if (!res.ok) {
        addLine('error', `whois: ${data.error || 'Query failed'}`);
        return;
      }

      addLine('output', data.raw);
    } catch (err: any) {
      addLine('error', `whois error: ${err.message}`);
    }
  };

  // Active DNS Subdomain Discovery
  const handleSubdomains = async (domain?: string) => {
    if (!domain) {
      addLine('error', 'Usage: subdomains <domain> (contoh: subdomains github.com atau subdomains cloudflare.com)');
      return;
    }

    addLine('output', `[Scanning active DNS subdomains for ${domain} in parallel...]`);

    try {
      const res = await fetch('/api/security/subdomains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });

      const data = await res.json();
      if (!res.ok) {
        addLine('error', `subdomains: ${data.error || 'Scan failed'}`);
        return;
      }

      let subRows = '';
      data.subdomains.forEach((item: any) => {
        subRows += ` [+] ${item.subdomain.padEnd(28)} --> ${item.ips.join(', ')}\n`;
      });

      if (data.subdomains.length === 0) {
        subRows = ' No standard active subdomains found responding to DNS.\n';
      }

      addLine('ascii', `===========================================================
             ATRIX DNS SUBDOMAIN DISCOVERY SCANNER         
===========================================================
 Target Domain : ${data.domain}
 Subdomains Tested : ${data.scanned} common prefixes
 Active Discovered : ${data.foundCount} live subdomains
 Scan Duration     : ${data.timeMs} ms
-----------------------------------------------------------
${subRows}===========================================================`);
    } catch (err: any) {
      addLine('error', `subdomains scan error: ${err.message}`);
    }
  };

  // CVE Vulnerability Search (Official NIST NVD)
  const handleCve = async (query?: string) => {
    if (!query) {
      addLine('error', 'Usage: cve <query_or_cve_id> (contoh: cve CVE-2021-44228 atau cve nginx atau cve openssh)');
      return;
    }

    addLine('output', `[Searching NIST National Vulnerability Database for "${query}"...]`);

    try {
      const res = await fetch('/api/security/cve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query })
      });

      const data = await res.json();
      if (!res.ok) {
        addLine('error', `cve search: ${data.error || 'Failed to query CVE database'}`);
        return;
      }

      if (data.results.length === 0) {
        addLine('output', `No CVE vulnerability records found for "${query}".`);
        return;
      }

      let cveText = '';
      data.results.forEach((c: any) => {
        cveText += `\n[ ${c.id} ]  CVSS Score: ${c.cvss} (${c.severity})\nPublished: ${c.published}\nDescription:\n  ${c.description.slice(0, 220)}...\n-----------------------------------------------------------`;
      });

      addLine('ascii', `===========================================================
          NIST NATIONAL VULNERABILITY DATABASE (NVD)       
===========================================================
 Query         : ${data.query}
 Records Found : ${data.totalResults}
-----------------------------------------------------------${cveText}
===========================================================`);
    } catch (err: any) {
      addLine('error', `cve query error: ${err.message}`);
    }
  };

  // Hash Type Identifier
  const handleHashId = (hashStr?: string): string => {
    if (!hashStr) {
      return 'Usage: hashid <hash_string>\nContoh: hashid 5d41402abc4b2a76b9719d911017c592\n        hashid $2a$12$e8NjhW3vgukUQD83v29hFeu1...';
    }

    const info = identifyHash(hashStr);
    return `===========================================================
               ATRIX HASH IDENTIFIER REPORT                
===========================================================
 Input Hash    : ${hashStr}
 Hash Length   : ${info.length} characters
 Character Set : ${info.charset}
 Possible Algorithm(s):
   ${info.possibleTypes.map(t => `-> ${t}`).join('\n   ')}
===========================================================`;
  };

  // Sandbox & Device Isolation Status
  const handleSandboxStatus = (): string => {
    return `===========================================================
            ATRIX VIRTUAL DEVICE & SANDBOX STATUS          
===========================================================
 Virtual Target    : Cloud Virtual Station (Android/Linux Sandbox)
 Isolation State   : AIR-GAPPED & BROWSER CONTAINED
 Host Device Access: BLOCKED (0 bytes written to host phone/PC)
 Storage Location  : Virtual Filesystem (LocalStorage Sandbox)
 Rate Limits       : UNLIMITED (Direct stream unpacker active)
 Network Egress    : Cloud Secured Proxy Adapter (CORS Bypass)
 Current User      : user@atrix (UID 1000, GID 1000)
 Available Tools   : urlscan, intel, wget, nano, python, nmap, cve,
                     whois, subfinder, hashid, speedtest, headers, ssl
===========================================================
Your physical phone/computer is 100% protected. All downloads,
scans, and scripts remain exclusively inside this tab!`;
  };

  // Python Script Runner & Evaluator
  const handlePython = (args: string[]): string => {
    if (args.length === 0) {
      return `Python 3.12.2 (main, ATRIX-VFS-VirtualRuntime) [GCC 13.2.0] on linux
Type "py -c '<code>'" or "py <script.py>" to execute Python scripts.`;
    }

    let code = '';
    if (args[0] === '-c') {
      code = args.slice(1).join(' ');
    } else {
      const fullPath = vfs.normalizePath(args[0], currentDir);
      const item = vfs.getItem(fullPath);
      if (!item || item.type !== 'file') {
        return `python: can't open file '${args[0]}': No such file or directory`;
      }
      code = item.content || '';
    }

    try {
      const logs: string[] = [];
      const pyPrint = (...vals: any[]) => logs.push(vals.map(v => typeof v === 'object' ? JSON.stringify(v) : String(v)).join(' '));
      
      let jsCode = code
        .replace(/#.*$/gm, '')
        .replace(/\bprint\((.*?)\)/g, 'print($1)')
        .replace(/\bTrue\b/g, 'true')
        .replace(/\bFalse\b/g, 'false')
        .replace(/\bNone\b/g, 'null')
        .replace(/\band\b/g, '&&')
        .replace(/\bor\b/g, '||')
        .replace(/\bnot\b/g, '!');

      const fn = new Function('print', `"use strict"; ${jsCode}`);
      fn(pyPrint);
      return logs.length > 0 ? logs.join('\n') : '[Python execution completed with no output]';
    } catch (err: any) {
      return `Traceback (most recent call last):\n  File "${args[0]}", line 1, in <module>\nPythonError: ${err.message}`;
    }
  };

  // Virtual Package Manager (pkg / apt / pacman)
  const handlePkg = (args: string[]): string => {
    if (args.length === 0 || args[0] === 'help') {
      return `Arch Linux / ATRIX Package Manager (pacman / pkg)
Usage:
  pacman -S <pkg>       Install package(s) into sandbox
  pacman -Ss <query>    Search for packages in Arch ARM repo
  pacman -Syu           Synchronize package databases and upgrade
  pacman -Q             Query installed packages
  pacman -R <pkg>       Remove package`;
    }

    const first = args[0].toLowerCase();
    if (first === '-syu' || first === 'update' || first === 'upgrade') {
      return `:: Synchronizing package databases...
 core is up to date
 extra is up to date
 community is up to date
:: Starting full system upgrade...
 there is nothing to do (system is up-to-date)`;
    }

    if (first === '-ss' || first === 'search') {
      const q = args[1] || 'sec';
      return `core/linux-aarch64 4.9.336-Kamui [installed]
    Arch Linux ARM kernel for Cortex-A53
extra/nmap 7.94-1 [installed]
    Network exploration tool and security / port scanner
extra/wireshark-cli 4.2.0-1 [installed]
    Network traffic and packet analyzer
community/sqlmap 1.7.12-1 [installed]
    Automatic SQL injection and database takeover tool
community/aircrack-ng 1.7-2 [installed]
    Key cracker for the 802.11 WEP and WPA-PSK protocols
community/metasploit 6.3.38-1 [installed]
    Penetration testing software platform`;
    }

    if (first === '-q' || first === 'list') {
      return `Installed Packages (201 packages):
  nmap 7.94-1, wireshark-cli 4.2.0-1, metasploit 6.3.38-1, sqlmap 1.7.12-1,
  aircrack-ng 1.7-2, nikto 2.5.0-1, hashcat 6.2.6-1, john 1.9.0-1,
  snort 3.1.72-1, ossec 3.7.0-1, maltego 4.3.0-1, autopsy 4.21.0-1,
  python 3.11.5-1, wget 1.21.4-1, zsh 5.9-1, base 3-2`;
    }

    if (first === '-s' || first === 'install') {
      const pkgName = args[1] || 'security-tool';
      return `resolving dependencies...
looking for conflicting packages...

Packages (1) ${pkgName}-1.0.0-1

Total Download Size:    1.42 MiB
Total Installed Size:   4.85 MiB

:: Proceeding with installation...
(1/1) checking keys in keyring                     [####################] 100%
(1/1) checking package integrity                   [####################] 100%
(1/1) loading package files                        [####################] 100%
(1/1) checking for file conflicts                  [####################] 100%
(1/1) checking available disk space                [####################] 100%
:: Processing package changes...
(1/1) installing ${pkgName}                        [####################] 100%
:: Running post-transaction hooks...
(1/1) Arming ConditionNeedsUpdate...
[✓] ${pkgName} is installed and available in /usr/bin!`;
    }

    return `pacman: unrecognized option '${args[0]}'. Try 'pacman -S <pkg>', 'pacman -Ss <query>', or 'pacman -Syu'`;
  };

  const handleLogoColor = (arg?: string): string | null => {
    if (!arg) {
      const currentPreset = Object.entries(LOGO_COLOR_PRESETS).find(
        ([_, v]) => v.hex.toLowerCase() === logoColor.toLowerCase()
      );
      const currentLabel = currentPreset ? `${currentPreset[0]} (${currentPreset[1].label})` : logoColor;
      return `Current logo color: ${logoColor} [${currentLabel}]\nAvailable: cyan, green, amber, blue, purple, red, yellow, white, pink, or #hex.\n(Tip: Klik langsung tombol warna di bawah terminal untuk ganti warna instan!)`;
    }

    const lower = arg.toLowerCase().trim();
    let targetHex = '';
    let name = lower;

    if (LOGO_COLOR_PRESETS[lower]) {
      targetHex = LOGO_COLOR_PRESETS[lower].hex;
      name = LOGO_COLOR_PRESETS[lower].label;
    } else if (/^#[0-9a-f]{3,8}$/i.test(lower)) {
      targetHex = lower;
      name = `Custom Hex (${lower})`;
    } else {
      return `logocolor: warna '${arg}' tidak valid. Pilihan: cyan, green, amber, blue, purple, red, yellow, white, pink, atau #hex.`;
    }

    updateLogoColor(targetHex);
    return `[ Logo color -> ${targetHex} (${name}) ]`;
  };

  const handleNeofetch = async () => {
    const sec = Math.floor((Date.now() - sessionStartTime.current) / 1000);
    const mins = Math.floor(sec / 60);
    const battery = await getBatteryTelemetry();
    const data = getNeofetchData(battery.display);
    data.uptime = `${mins} min(s), ${sec % 60} sec(s)`;
    addLine('neofetch', '', undefined, undefined, data);
  };

  const handleExport = (expr: string): string => {
    if (!expr || !expr.includes('=')) return 'Usage: export KEY=VALUE';
    const [key, ...vals] = expr.split('=');
    const val = vals.join('=');
    setEnvVars(prev => ({ ...prev, [key.trim()]: val.trim() }));
    return '';
  };

  const handleCowsay = (text: string): string => {
    const len = text.length;
    const border = '-'.repeat(len + 2);
    return `
 ${border}
< ${text} >
 ${border}
        \\   ^__^
         \\  (oo)\\_______
            (__)\\       )\\/\\
                ||----w |
                ||     ||`;
  };

  const getFortune = (): string => {
    const quotes = [
      '"Simplicity is prerequisite for reliability." - Edsger W. Dijkstra',
      '"Talk is cheap. Show me the code." - Linus Torvalds',
      '"There are only two hard things in Computer Science: cache invalidation and naming things." - Phil Karlton',
      '"First, solve the problem. Then, write the code." - John Johnson',
      '"Code never lies, comments sometimes do." - Ron Jeffries',
      '"Premature optimization is the root of all evil." - Donald Knuth',
      '"Unix is simple. It just takes a genius to understand its simplicity." - Dennis Ritchie'
    ];
    return quotes[Math.floor(Math.random() * quotes.length)];
  };

  const handleAi = async (prompt: string) => {
    if (!prompt) {
      addLine('error', 'Usage: ai <pertanyaan atau perintah yang ingin dicari>');
      return;
    }
    addLine('output', `* Consulting AI assistant: "${prompt}"...`);
    try {
      const res = await fetch('/api/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt })
      });
      const data = await res.json();
      if (!res.ok) {
        addLine('error', `AI Service: ${data.error || 'Request failed'}`);
        return;
      }
      addLine('output', data.reply);
    } catch (err: any) {
      addLine('error', `AI Request error: ${err.message}`);
    }
  };

  const getHelpText = (): string => {
    return `ATRIX OS - CYBER SECURITY & OSINT WORKSTATION MANUAL
==============================================================
== ATRIX INTELLIGENCE & THREAT OSINT ==
  intel [target] / osint [t]   : Real-time CLI Threat Intelligence (IP, Domain, Email, DNS/TLS audit, Threat Index)
  urlscan <url> / scanurl <u*> : Live URL Security Scanner (Redirect tracer, Phishing, SSL, Headers & HTML)

== NETWORK & DOMAIN RECON ==
  nmap [mode] <target> [ports] : Nmap scanner (basic|quick|deep|udp|vuln|os|web|ping)
  myip / ip                    : Show your public IP, ISP, ASN, location & network
  ip <ip|domain>               : Real IP geolocation, ISP, ASN, timezone & reverse DNS
  dns <domain> [A|MX|TXT...]   : DNS records lookup via system resolver
  rdns <ipv4>                  : Reverse DNS (PTR) hostname lookup
  whois <domain>               : Domain registration & RDAP registry records
  subdomains <domain>          : Passive Cert Transparency (crt.sh) + Active DNS discovery
  wayback <url>                : Closest Internet Archive Wayback Machine snapshot
  tools <domain|ip>            : Direct intelligence jump links (Shodan, VT, Censys...)

== PEOPLE & SOCIAL (OSINT / STALK) ==
  sherlock <user> / stalk <u*> : REAL LIVE username presence check on 16 platforms
                                 (GitHub, Reddit, Docker, Dev.to, HN, GitLab, npm, PyPI, Medium, Gravatar, Telegram, Chess.com...)
  who <name>                   : Profile & facts about a person/entity (Wikipedia)
  username <name>              : Search biography & identity facts
  socials <username>           : Direct profile links across 30+ platforms
  github <user>                : GitHub profile intelligence, follower stats & bio
  ghrepos <user>               : Latest public repositories of a GitHub user
  ghemail <user>               : Unmasked emails from public commit events
  email <address>              : Validate email syntax, MX mail exchange & burner test
  gravatar <email>             : Gravatar profile intelligence, avatar & linked socials
  phone <+country><number>     : Country, carrier hints & verification links

== WEB & DEFENSIVE SECURITY AUDIT ==
  info <url>                   : Deep website intel: apa fungsi website, kategori, audiens, fitur & status
  techstack <domain>           : Real CMS, Web Server, Framework (React/Next/Vue/Tailwind) & WAF profiler
  emailsec <domain>            : SPF, DMARC, DKIM email spoofing vulnerability audit
  robots <domain>              : Extract sensitive disallow paths from target's robots.txt
  securitytxt <domain>         : RFC 9116 security bug bounty disclosure contact & policy
  headers <url>                : Audit defensive HTTP security headers (HSTS, CSP, X-Frame)
  cors <url>                   : Test CORS origin reflection & credentials leakage vulnerability
  ssl <host>                   : Real TLS handshake, certificate validity, expiration & cipher
  portscan <host>              : Direct TCP socket port scanning (21, 22, 80, 443, 3306, 5432, 6379, 8080)
  cve <id|query>               : Query NIST National Vulnerability Database (CVSS score)
  crack <hash>                 : Multi-algorithm rainbow dictionary hash cracker (MD5, SHA1, SHA256)
  hashid <hash>                : Identify hash algorithm (MD5, SHA256, bcrypt, NTLM...)
  hash <algo> <text>           : Hash generator (sha256, sha512, sha1, md5)
  passcheck <password>         : Password entropy & brute-force resistance time
  jwt <token>                  : Decode JWT token claims without verification

== TOP-TIER BUG BOUNTY TOOLKIT ==
  subtakeover <domain>         : Audit dangling DNS CNAME takeover (S3, GitHub Pages, Heroku, Azure...)
  bounty <domain> / vdp <d>    : HackerOne, Bugcrowd & security.txt scope & policy reconnaissance
  cvss [vector]                : CVSS v3.1 severity base score & triage priority calculator
  report <type> <domain>       : Generate professional HackerOne/Bugcrowd triage report draft
                                 (Types: takeover, idor, cors, dmarc)

== WHATSAPP PRIVACY & ANTI-DOXXING ==
  wa-protect [nomor]           : Panduan darurat 7 langkah amankan WA yang disebar/didoxx
  wa-check <nomor>             : Cek format nomor WA, operator (Telkomsel/Indosat/XL...), direct link & jejak spam
  wa-link <nomor> [pesan]      : Buat link chat langsung wa.me tanpa save kontak + template pesan

== CYBER SECURITY COMPETITION & CTF ARENA ==
  ctf [list|play|hint|submit|score] : Arena latihan lomba Cyber Security (Forensics, Crypto, Web, Reverse)
  wireshark [-r|view|follow|-Y]     : Interactive packet analyzer, OSI deep dissection & Follow TCP Stream
  nmap [-sV|-sC|-p|-O|-A] <target>  : Live TCP network port auditor & banner grabber
  strings <file>                    : Ekstrak teks tersembunyi / flag dari file binary & memory dump
  binwalk <file>                    : Deteksi signature file, magic bytes & steganografi
  lomba / cyber-cheat               : Cheat sheet taktis & strategi juara lomba cyber security / CTF

== 15 CYBER SECURITY FRAMEWORKS ==
  01. nmap <target>            : Network port & service version scanner
  02. wireshark [filter]       : Live packet capture inspector (TCP, DNS, TLS...)
  03. metasploit [search|use]  : Modular exploit framework console
  04. burpsuite [proxy|rep]    : Web testing HTTP proxy & raw repeater
  05. openvas <target>         : Vulnerability assessment & CVSS report
  06. nikto <target>           : Web server misconfigurations & CGI scanner
  07. hashcat [benchmark|hash] : GPU/CPU rule-based password cracking & dictionary
  08. sqlmap <url>             : Automated SQL injection tester & DB banner grabber
  09. aircrack-ng [scan|crack] : WiFi 802.11 monitor & WPA handshake recovery
  10. john <hash>              : John the Ripper dictionary & brute force cracker
  11. snort                    : Network intrusion detection (NIDS) alert engine
  12. ossec                    : Host IDS, file integrity monitoring & log auditor
  13. maltego <target>         : OSINT relationship graph & entity transforms
  14. setoolkit                : Social-Engineer Toolkit & payload generator
  15. autopsy [image]          : Digital forensics, file carving & timeline

== GEO & UTILITIES ==
  geo <place name>             : Geocode a place (OpenStreetMap Nominatim)
  revgeo <lat> <lon>           : Coordinates to physical address lookup
  country <name>               : Country facts, capital, currencies & borders
  dork <domain|keyword>        : Google dork reconnaissance generator
  search <query>               : Multi-engine web search queries
  b64 / base64 <enc|dec> <txt> : Base64 encoder and decoder
  hex <enc|dec> <text>         : Hexadecimal encoder and decoder
  url / urlencode <text>       : URL encoder and decoder
  rot13 <text>                 : ROT13 cipher transformation
  ts <unix|now>                : Unix timestamp converter
  subnet <cidr>                : IPv4 CIDR and subnet mask calculator
  calc <expression>            : Scientific calculator
  fingerprint                  : Hardware & browser fingerprint

== ARCH LINUX ARM & SANDBOX SYSTEM ==
  sandbox / device             : Virtual air-gap isolation status (HP Kedua mode)
  battery                      : Hardware battery percentage & charging telemetry
  mount                        : Display mounted filesystems (/dev, /sys, /sdcard...)
  umount <mountpoint>          : Unmount virtual filesystem
  df [-h]                      : Filesystem storage disk space usage
  chroot <dir>                 : Execute chroot subsystem sequence
  pacman -S <pkg> | -Ss | -Syu : Arch Linux ARM package manager
  wget <url> [filename]        : Download file directly into sandbox storage
  nano <file>                  : Full in-terminal text editor
  top / htop                   : Live interactive process monitor
  neofetch                     : ATRIX OS specifications & system info
  clear                        : Clear terminal screen
==============================================================`;
  };

  return (
    <div
      style={{ fontSize: `${fontSize}px` }}
      className="min-h-screen bg-black text-white font-mono p-4 cursor-text select-text"
      onClick={() => {
        if (activeApp === 'terminal') {
          inputRef.current?.focus({ preventScroll: true });
        }
      }}
    >
      <div id="terminal" className="max-w-[900px] mx-auto min-h-screen flex flex-col justify-between">
        {/* Main Terminal Body */}
        <div>
          {/* Active Specialized Sub-App */}
          {activeApp === 'nano' && (
            <NanoEditor
              filePath={nanoTargetFile}
              initialContent={nanoInitialContent}
              onExit={(msg) => {
                setActiveApp('terminal');
                if (msg) addLine('system', `[ ${msg} ]`);
              }}
            />
          )}

          {activeApp === 'top' && (
            <TopMonitor onExit={() => setActiveApp('terminal')} />
          )}

          {activeApp === 'matrix' && (
            <MatrixRain onExit={() => setActiveApp('terminal')} />
          )}

          {/* Lines History */}
          {activeApp === 'terminal' && (
            <div ref={terminalRef} className="space-y-1">
              {lines.map((line) => {
                if (line.id === 'boot-mounts') {
                  return (
                    <div key={line.id} className="text-xs sm:text-sm font-mono leading-relaxed space-y-1 my-2 select-text">
                      <div className="text-white/40">#################################</div>
                      <div className="text-[#38bdf8] font-bold mt-2">[ Mouting system folders ]</div>
                      <div className="text-white/90 pl-2 space-y-0.5">
                        <div><span className="text-[#38bdf8]">[</span> Mouting suid, dev <span className="text-[#38bdf8]">]</span></div>
                        <div><span className="text-[#38bdf8]">[</span> Mouting /dev <span className="text-[#38bdf8]">]</span></div>
                        <div><span className="text-[#38bdf8]">[</span> Mouting /sys <span className="text-[#38bdf8]">]</span></div>
                        <div><span className="text-[#38bdf8]">[</span> Mouting /proc <span className="text-[#38bdf8]">]</span></div>
                        <div><span className="text-[#38bdf8]">[</span> Mouting /dev/pts <span className="text-[#38bdf8]">]</span></div>
                        <div><span className="text-[#38bdf8]">[</span> Mouting /dev/shm <span className="text-[#38bdf8]">]</span></div>
                        <div><span className="text-[#38bdf8]">[</span> Mouting /tmp <span className="text-[#38bdf8]">]</span></div>
                        <div><span className="text-[#38bdf8]">[</span> Mounting /run <span className="text-[#38bdf8]">]</span></div>
                        <div><span className="text-[#38bdf8]">[</span> Mouting /sdcard <span className="text-[#38bdf8]">]</span></div>
                      </div>
                      <div className="text-[#38bdf8] font-bold mt-2">[ Mouting Done! ]</div>
                      <div className="text-[#38bdf8] font-semibold">&gt; chrooting</div>
                    </div>
                  );
                }

                if (line.type === 'neofetch') {
                  const d = line.neofetchData || getNeofetchData();
                  return (
                    <div key={line.id} className="my-2 select-text font-mono flex flex-col items-start space-y-2">
                      {/* Logo on top */}
                      <pre
                        style={{ color: logoColor }}
                        className="text-[12px] sm:text-[14px] leading-[1.2] font-bold select-text overflow-x-auto my-1"
                      >
                        {ATRIX_LOGO_ASCII}
                      </pre>

                      {/* System Info moved below the logo with clean, clear typography */}
                      <div className="text-xs sm:text-[13px] leading-relaxed space-y-0.5 max-w-full">
                        <div className="font-bold underline text-white">{d.userHost}</div>
                        <div className="text-white/40">---------------------</div>
                        <div><span className="font-semibold text-white/90">OS:</span> <span className="text-white/80">{d.os}</span></div>
                        <div><span className="font-semibold text-white/90">Host:</span> <span className="text-white/80">{d.host}</span></div>
                        <div><span className="font-semibold text-white/90">Kernel:</span> <span className="text-white/80">{d.kernel}</span></div>
                        <div><span className="font-semibold text-white/90">Uptime:</span> <span className="text-white/80">{d.uptime}</span></div>
                        <div><span className="font-semibold text-white/90">Packages:</span> <span className="text-white/80">{d.packages}</span></div>
                        <div><span className="font-semibold text-white/90">Shell:</span> <span className="text-white/80">{d.shell}</span></div>
                        <div><span className="font-semibold text-white/90">Terminal:</span> <span className="text-white/80">{d.terminal}</span></div>
                        <div><span className="font-semibold text-white/90">CPU:</span> <span className="text-white/80">{d.cpu}</span></div>
                        <div><span className="font-semibold text-white/90">Memory:</span> <span className="text-white/80">{d.memory}</span></div>
                        <div><span className="font-semibold text-white/90">Swap:</span> <span className="text-white/80">{d.swap}</span></div>
                        <div><span className="font-semibold text-white/90">Local IP (wlan0):</span> <span className="text-white/80">{d.localIp}</span></div>
                        <div><span className="font-semibold text-white/90">Battery:</span> <span className="text-white/80">{d.battery}</span></div>
                        <div><span className="font-semibold text-white/90">Locale:</span> <span className="text-white/80">{d.locale}</span></div>

                        {/* ANSI Color Palette Blocks */}
                        <div className="pt-2 flex flex-col gap-1">
                          <div className="flex gap-1.5">
                            {['#262626', '#ef4444', '#22c55e', '#eab308', '#3b82f6', '#a855f7', '#06b6d4', '#e5e5e5'].map((c, i) => (
                              <span key={i} className="inline-block w-4 h-3.5 sm:w-5 sm:h-4 rounded-[1px]" style={{ backgroundColor: c }} />
                            ))}
                          </div>
                          <div className="flex gap-1.5">
                            {['#525252', '#f87171', '#4ade80', '#fde047', '#60a5fa', '#c084fc', '#38bdf8', '#ffffff'].map((c, i) => (
                              <span key={i} className="inline-block w-4 h-3.5 sm:w-5 sm:h-4 rounded-[1px]" style={{ backgroundColor: c }} />
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                }

                if (line.type === 'logo') {
                  return (
                    <pre
                      key={line.id}
                      style={{ color: logoColor }}
                      className="font-mono text-[12px] sm:text-[14px] leading-[1.2] my-1 font-semibold overflow-x-auto select-text"
                    >
                      {ATRIX_LOGO_ASCII}
                    </pre>
                  );
                }

                if (line.type === 'ascii') {
                  return (
                    <pre
                      key={line.id}
                      style={line.color ? { color: line.color } : undefined}
                      className="text-white font-mono text-[12px] sm:text-[13px] leading-[1.1] my-1 overflow-x-auto"
                    >
                      {line.content}
                    </pre>
                  );
                }

                if (line.type === 'input') {
                  return (
                    <div key={line.id} className="my-1 font-mono">
                      <div className="text-[#38bdf8] select-none text-xs">{line.prompt || `-codak@localhost ~`}</div>
                      <div className="flex items-start">
                        <span className="text-white whitespace-pre select-none font-bold">└─${' '}</span>
                        <span className="text-white break-all">{line.content}</span>
                      </div>
                    </div>
                  );
                }

                if (line.type === 'error') {
                  return (
                    <div key={line.id} className="text-white/90 underline decoration-white/40 my-0.5">
                      {line.content}
                    </div>
                  );
                }

                if (line.type === 'system') {
                  return (
                    <div key={line.id} className="text-white/70 italic my-0.5">
                      {line.content}
                    </div>
                  );
                }

                return (
                  <div key={line.id} className="whitespace-pre-wrap break-words leading-snug my-0.5 font-mono">
                    {line.content}
                  </div>
                );
              })}

              {/* Active Prompt Line matching Image 1 */}
              <div className="input-block mt-2 font-mono">
                <div className="text-[#38bdf8] select-none text-xs">
                  {getPromptHeader()}
                </div>
                <div className="input-line flex items-center relative min-h-[22px]">
                  <span className="prompt-text text-white whitespace-nowrap font-bold select-none font-mono">
                    {getPromptString()}
                  </span>

                  <span className="text-white inline-block break-all font-mono">
                    {inputVal}
                  </span>

                  {/* Exact Blinking Block Cursor */}
                  <span className="cursor-blink" />

                  {/* Invisible input element to capture typing accurately on desktop & mobile */}
                  <input
                    ref={inputRef}
                    type="text"
                    value={inputVal}
                    onChange={(e) => setInputVal(e.target.value)}
                    onKeyDown={handleKeyDown}
                    disabled={isProcessing}
                    autoComplete="off"
                    autoCapitalize="off"
                    autoCorrect="off"
                    spellCheck={false}
                    className="absolute inset-0 opacity-0 cursor-text w-full h-full z-10"
                  />
                </div>
              </div>

              {isProcessing && (
                <div className="text-white/60 text-xs mt-1 animate-pulse font-mono">
                  [Processing...]
                </div>
              )}

              {/* Anchor for smooth scroll on new output */}
              <div ref={promptEndRef} className="h-0 w-0 pointer-events-none" />
            </div>
          )}
        </div>

        {/* Mobile & Touch Helper Quick Toolbar */}
        {activeApp === 'terminal' && (
          <div className="mt-8 pt-2 border-t border-white/20 select-none pb-4 text-xs space-y-2 font-mono">
            {/* Interactive Logo Color Palette - In-Place Silent Color Switching */}
            <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-white/90">
              <span className="text-white/60 font-mono select-none">Logo Color:</span>
              {Object.entries(LOGO_COLOR_PRESETS).map(([key, preset]) => {
                const isSelected = logoColor.toLowerCase() === preset.hex.toLowerCase();
                return (
                  <button
                    key={key}
                    type="button"
                    title={preset.label}
                    onClick={() => {
                      updateLogoColor(preset.hex);
                      inputRef.current?.focus({ preventScroll: true });
                    }}
                    className={`px-2 py-0.5 border flex items-center gap-1 font-mono transition-all cursor-pointer ${
                      isSelected
                        ? 'border-white bg-white/20 text-white font-bold'
                        : 'border-white/20 text-white/70 hover:border-white/60 hover:text-white'
                    }`}
                  >
                    <span
                      className="w-2.5 h-2.5 rounded-full inline-block border border-black/40"
                      style={{ backgroundColor: preset.hex }}
                    />
                    <span>{key}</span>
                  </button>
                );
              })}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] text-white/80">
              <div className="flex flex-wrap gap-1">
                <button
                  type="button"
                  onClick={() => handleTabCompletion()}
                  className="px-2 py-0.5 border border-white/30 hover:bg-white hover:text-black cursor-pointer"
                >
                  Tab
                </button>
                <button
                  type="button"
                  onClick={() => {
                    if (history.length > 0) {
                      const next = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
                      setHistoryIndex(next);
                      setInputVal(history[next]);
                    }
                  }}
                  className="px-2 py-0.5 border border-white/30 hover:bg-white hover:text-black cursor-pointer"
                >
                  ▲ Prev
                </button>
                <button
                  type="button"
                  onClick={() => {
                    if (historyIndex >= 0 && historyIndex < history.length - 1) {
                      const next = historyIndex + 1;
                      setHistoryIndex(next);
                      setInputVal(history[next]);
                    } else {
                      setHistoryIndex(-1);
                      setInputVal('');
                    }
                  }}
                  className="px-2 py-0.5 border border-white/30 hover:bg-white hover:text-black cursor-pointer"
                >
                  ▼ Next
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('');
                    addLine('input', '^C', getPromptString());
                  }}
                  className="px-2 py-0.5 border border-white/30 hover:bg-white hover:text-black cursor-pointer"
                >
                  Ctrl+C
                </button>
                <button
                  type="button"
                  onClick={() => setLines([])}
                  className="px-2 py-0.5 border border-white/30 hover:bg-white hover:text-black cursor-pointer"
                >
                  Clear
                </button>
              </div>

              <div className="flex flex-wrap gap-1">
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('intel ');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  intel
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('logo');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  logo
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('logocolor');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  logocolor
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('help');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  help
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('speedtest');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  speedtest
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('ip');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  ip
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('neofetch');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  neofetch
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('sandbox');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer text-white"
                >
                  sandbox
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('portscan scanme.nmap.org');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  portscan
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('whois google.com');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  whois
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('subdomains github.com');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  subdomains
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('cve OpenSSL');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  cve
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('top');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  top
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('urlscan https://');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  urlscan
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('headers github.com');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  headers
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('ssl google.com');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  ssl
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('passcheck P@ssw0rdKeren2026!');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  passcheck
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('nmap basic scanme.nmap.org');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer text-[#38bdf8]"
                >
                  nmap
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('wireshark');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  wireshark
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('metasploit search log4j');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  metasploit
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('sqlmap http://testphp.vulnweb.com/listproducts.php?cat=1');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  sqlmap
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('socials torvalds');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  socials
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('sherlock torvalds');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer text-[#38bdf8]"
                >
                  sherlock
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('techstack github.com');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer text-amber-300"
                >
                  techstack
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('emailsec google.com');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  emailsec
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('robots github.com');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  robots
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('cors https://api.github.com');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  cors
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('gravatar beau@dentedreality.com.au');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  gravatar
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('crack 5d41402abc4b2a76b9719d911017c592');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer text-emerald-400"
                >
                  crack
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('dork example.com');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  dork
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('battery');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer text-emerald-400"
                >
                  battery
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('mount');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  mount
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('df -h');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  df
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setInputVal('matrix');
                    inputRef.current?.focus({ preventScroll: true });
                  }}
                  className="px-2 py-0.5 border border-white/20 hover:bg-white hover:text-black cursor-pointer"
                >
                  matrix
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
