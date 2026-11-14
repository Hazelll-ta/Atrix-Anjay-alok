// Real cryptographic and developer utilities

export async function computeHash(algo: 'SHA-256' | 'SHA-512' | 'SHA-1' | 'MD5', text: string): Promise<string> {
  if (algo === 'MD5') {
    // Standard fast MD5 implementation in pure TS
    return md5(text);
  }

  const msgUint8 = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest(algo, msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function base64Encode(text: string): string {
  try {
    return btoa(unescape(encodeURIComponent(text)));
  } catch (err: any) {
    throw new Error(`Failed to base64 encode: ${err.message}`);
  }
}

export function base64Decode(text: string): string {
  try {
    return decodeURIComponent(escape(atob(text)));
  } catch (err: any) {
    throw new Error(`Invalid Base64 string: ${err.message}`);
  }
}

export function parseJwt(token: string): { header: any; payload: any; isExpired: boolean; expDate?: string } {
  const parts = token.split('.');
  if (parts.length < 2) {
    throw new Error('Invalid JWT format (must have at least header.payload)');
  }

  const decodePart = (str: string) => {
    let output = str.replace(/-/g, '+').replace(/_/g, '/');
    switch (output.length % 4) {
      case 0: break;
      case 2: output += '=='; break;
      case 3: output += '='; break;
      default: throw new Error('Illegal base64url string');
    }
    return JSON.parse(decodeURIComponent(escape(atob(output))));
  };

  const header = decodePart(parts[0]);
  const payload = decodePart(parts[1]);

  let isExpired = false;
  let expDate: string | undefined;

  if (payload.exp) {
    const expMs = payload.exp * 1000;
    isExpired = Date.now() > expMs;
    expDate = new Date(expMs).toUTCString();
  }

  return { header, payload, isExpired, expDate };
}

// Defensive Security: Password Entropy & Crack-Time Analyzer
export function analyzePassword(password: string) {
  const len = password.length;
  let pool = 0;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigits = /[0-9]/.test(password);
  const hasSymbols = /[^a-zA-Z0-9]/.test(password);

  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigits) pool += 10;
  if (hasSymbols) pool += 33;

  // Entropy = L * log2(pool)
  const entropy = pool > 0 ? Math.round(len * (Math.log(pool) / Math.log(2))) : 0;

  // Combinations = pool ^ len
  // Assumptions: Fast offline hash cracking rig (100 billion guesses/sec, e.g. 8x RTX 4090 NTLM/MD5)
  const guessesPerSec = 100_000_000_000;
  const totalCombinations = Math.pow(pool, len);
  const secondsToCrack = totalCombinations / guessesPerSec;

  let crackTime = 'Instant (under 1 second)';
  if (secondsToCrack < 1) crackTime = 'Instant (< 1 second)';
  else if (secondsToCrack < 60) crackTime = `${Math.round(secondsToCrack)} seconds`;
  else if (secondsToCrack < 3600) crackTime = `${Math.round(secondsToCrack / 60)} minutes`;
  else if (secondsToCrack < 86400) crackTime = `${Math.round(secondsToCrack / 3600)} hours`;
  else if (secondsToCrack < 31536000) crackTime = `${Math.round(secondsToCrack / 86400)} days`;
  else if (secondsToCrack < 31536000 * 1000) crackTime = `${Math.round(secondsToCrack / 31536000)} years`;
  else if (secondsToCrack < 31536000 * 1_000_000) crackTime = `${(secondsToCrack / (31536000 * 1000)).toFixed(1)} thousand years`;
  else crackTime = 'Centuries / Billions of years';

  let rating = 'CRITICAL (Very Weak)';
  if (entropy >= 80 && len >= 14) rating = 'EXCELLENT (Very Strong)';
  else if (entropy >= 60 && len >= 12) rating = 'STRONG (Good)';
  else if (entropy >= 45 && len >= 8) rating = 'FAIR (Moderate)';
  else if (entropy >= 28) rating = 'WEAK (Vulnerable)';

  return {
    length: len,
    entropy,
    rating,
    crackTime,
    characterSet: {
      hasLower,
      hasUpper,
      hasDigits,
      hasSymbols
    },
    recommendations: [
      len < 12 ? 'Increase length to at least 12-16 characters' : null,
      !hasSymbols ? 'Add symbols (!@#$%^&*) to expand search space' : null,
      !hasUpper ? 'Add uppercase letters' : null,
      !hasDigits ? 'Add numbers' : null
    ].filter(Boolean) as string[]
  };
}

// Network Defense: IPv4 CIDR & Subnet Calculator
export function calculateSubnet(cidrInput: string) {
  const parts = cidrInput.trim().split('/');
  if (parts.length !== 2) throw new Error('Format must be IP/CIDR (e.g. 192.168.1.0/24)');

  const ip = parts[0];
  const cidr = parseInt(parts[1], 10);
  if (isNaN(cidr) || cidr < 0 || cidr > 32) throw new Error('CIDR mask must be between 0 and 32');

  const ipParts = ip.split('.').map(Number);
  if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) {
    throw new Error('Invalid IPv4 address format');
  }

  const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
  const maskInt = cidr === 0 ? 0 : (~0 << (32 - cidr)) >>> 0;
  const wildcardInt = ~maskInt >>> 0;
  const networkInt = (ipInt & maskInt) >>> 0;
  const broadcastInt = (networkInt | wildcardInt) >>> 0;

  const intToIp = (val: number) => [
    (val >>> 24) & 255,
    (val >>> 16) & 255,
    (val >>> 8) & 255,
    val & 255
  ].join('.');

  const totalHosts = Math.pow(2, 32 - cidr);
  const usableHosts = cidr >= 31 ? (cidr === 31 ? 2 : 1) : Math.max(0, totalHosts - 2);

  const firstUsable = cidr >= 31 ? intToIp(networkInt) : intToIp(networkInt + 1);
  const lastUsable = cidr >= 31 ? intToIp(broadcastInt) : intToIp(broadcastInt - 1);

  return {
    cidr: `${ip}/${cidr}`,
    network: intToIp(networkInt),
    netmask: intToIp(maskInt),
    wildcard: intToIp(wildcardInt),
    broadcast: intToIp(broadcastInt),
    firstUsable,
    lastUsable,
    totalHosts,
    usableHosts
  };
}

// Security Encoding / Decoding Utilities
export function rot13(str: string): string {
  return str.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

export function hexEncode(str: string): string {
  return Array.from(new TextEncoder().encode(str))
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');
}

export function hexDecode(hexStr: string): string {
  const clean = hexStr.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error('Hex string must have even length');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

export function urlEncode(str: string): string {
  return encodeURIComponent(str);
}

export function urlDecode(str: string): string {
  return decodeURIComponent(str);
}

export function generateUUID(): string {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export function evaluateCalc(expression: string): string {
  // Simple unit conversions
  const unitRegex = /^([\d.]+)\s*(km|miles?|c|f|kg|lbs?|mb|gb|kb|bytes?)\s+to\s+(km|miles?|c|f|kg|lbs?|mb|gb|kb|bytes?)$/i;
  const match = expression.trim().match(unitRegex);
  if (match) {
    const val = parseFloat(match[1]);
    const from = match[2].toLowerCase();
    const to = match[3].toLowerCase();

    // Km <-> Miles
    if (from.startsWith('km') && to.startsWith('mile')) {
      return `${val} km = ${(val * 0.621371).toFixed(4)} miles`;
    }
    if (from.startsWith('mile') && to.startsWith('km')) {
      return `${val} miles = ${(val * 1.60934).toFixed(4)} km`;
    }

    // Celsius <-> Fahrenheit
    if (from === 'c' && to === 'f') {
      return `${val}°C = ${((val * 9/5) + 32).toFixed(2)}°F`;
    }
    if (from === 'f' && to === 'c') {
      return `${val}°F = ${(((val - 32) * 5) / 9).toFixed(2)}°C`;
    }

    // Kg <-> Lbs
    if (from === 'kg' && to.startsWith('lb')) {
      return `${val} kg = ${(val * 2.20462).toFixed(4)} lbs`;
    }
    if (from.startsWith('lb') && to === 'kg') {
      return `${val} lbs = ${(val * 0.453592).toFixed(4)} kg`;
    }

    // Data sizes
    if (from === 'gb' && to === 'mb') return `${val} GB = ${val * 1024} MB`;
    if (from === 'mb' && to === 'gb') return `${val} MB = ${(val / 1024).toFixed(4)} GB`;
    if (from === 'mb' && to === 'kb') return `${val} MB = ${val * 1024} KB`;
    if (from === 'kb' && to === 'mb') return `${val} KB = ${(val / 1024).toFixed(4)} MB`;
  }

  // Safe math evaluator
  // Allow numbers, math operators, parentheses, commas, Math functions
  const sanitized = expression
    .replace(/\^/g, '**')
    .replace(/\bsin\b/g, 'Math.sin')
    .replace(/\bcos\b/g, 'Math.cos')
    .replace(/\btan\b/g, 'Math.tan')
    .replace(/\bsqrt\b/g, 'Math.sqrt')
    .replace(/\bpi\b/gi, 'Math.PI')
    .replace(/\be\b/gi, 'Math.E')
    .replace(/\blog\b/g, 'Math.log10')
    .replace(/\bln\b/g, 'Math.log')
    .replace(/\babs\b/g, 'Math.abs');

  // Verify only allowed characters
  if (!/^[0-9+\-*/().,% Math.sincotanqrtPIElgabs\s*]+$/.test(sanitized)) {
    throw new Error('Invalid math expression syntax');
  }

  // Execute using Function constructor in isolation
  const fn = new Function(`"use strict"; return (${sanitized});`);
  const result = fn();
  return String(result);
}

export function lineDiff(text1: string, text2: string): string[] {
  const lines1 = text1.split('\n');
  const lines2 = text2.split('\n');
  const result: string[] = [];

  const max = Math.max(lines1.length, lines2.length);
  for (let i = 0; i < max; i++) {
    const l1 = lines1[i];
    const l2 = lines2[i];
    if (l1 === l2) {
      result.push(`  ${l1 || ''}`);
    } else {
      if (l1 !== undefined) result.push(`- ${l1}`);
      if (l2 !== undefined) result.push(`+ ${l2}`);
    }
  }
  return result;
}

// Pure JS MD5 implementation
function md5(str: string): string {
  let x = Array<number>();
  let k, AA, BB, CC, DD, a, b, c, d;
  const S11=7, S12=12, S13=17, S14=22;
  const S21=5, S22=9, S23=14, S24=20;
  const S31=4, S32=11, S33=16, S34=23;
  const S41=6, S42=10, S43=15, S44=21;

  function utf8Encode(string: string) {
    string = string.replace(/\r\n/g, '\n');
    let utftext = '';
    for (let n = 0; n < string.length; n++) {
      const c = string.charCodeAt(n);
      if (c < 128) {
        utftext += String.fromCharCode(c);
      } else if ((c > 127) && (c < 2048)) {
        utftext += String.fromCharCode((c >> 6) | 192);
        utftext += String.fromCharCode((c & 63) | 128);
      } else {
        utftext += String.fromCharCode((c >> 12) | 224);
        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
        utftext += String.fromCharCode((c & 63) | 128);
      }
    }
    return utftext;
  }

  function convertToWordArray(string: string) {
    let lWordCount;
    const lMessageLength = string.length;
    const lNumberOfWords_temp1 = lMessageLength + 8;
    const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
    const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
    const lWordArray = Array(lNumberOfWords - 1);
    let lBytePosition = 0;
    let lByteCount = 0;
    while (lByteCount < lMessageLength) {
      lWordCount = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
      lByteCount++;
    }
    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
    lBytePosition = (lByteCount % 4) * 8;
    lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
    lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
    lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
    return lWordArray;
  }

  function wordToHex(lValue: number) {
    let WordToHexValue = '', WordToHexValue_temp = '', lByte, lCount;
    for (lCount = 0; lCount <= 3; lCount++) {
      lByte = (lValue >>> (lCount * 8)) & 255;
      WordToHexValue_temp = '0' + lByte.toString(16);
      WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
    }
    return WordToHexValue;
  }

  function F(x: number, y: number, z: number) { return (x & y) | ((~x) & z); }
  function G(x: number, y: number, z: number) { return (x & z) | (y & (~z)); }
  function H(x: number, y: number, z: number) { return (x ^ y ^ z); }
  function I(x: number, y: number, z: number) { return (y ^ (x | (~z))); }

  function FF(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = (a + F(b, c, d) + x + ac) & 0xffffffff;
    return (((a << s) | (a >>> (32 - s))) + b) & 0xffffffff;
  }
  function GG(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = (a + G(b, c, d) + x + ac) & 0xffffffff;
    return (((a << s) | (a >>> (32 - s))) + b) & 0xffffffff;
  }
  function HH(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = (a + H(b, c, d) + x + ac) & 0xffffffff;
    return (((a << s) | (a >>> (32 - s))) + b) & 0xffffffff;
  }
  function II(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = (a + I(b, c, d) + x + ac) & 0xffffffff;
    return (((a << s) | (a >>> (32 - s))) + b) & 0xffffffff;
  }

  str = utf8Encode(str);
  x = convertToWordArray(str);
  a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;

  for (k = 0; k < x.length; k += 16) {
    AA = a; BB = b; CC = c; DD = d;
    a = FF(a, b, c, d, x[k+0],  S11, 0xD76AA478);
    d = FF(d, a, b, c, x[k+1],  S12, 0xE8C7B756);
    c = FF(c, d, a, b, x[k+2],  S13, 0x242070DB);
    b = FF(b, c, d, a, x[k+3],  S14, 0xC1BDCEEE);
    a = FF(a, b, c, d, x[k+4],  S11, 0xF57C0FAF);
    d = FF(d, a, b, c, x[k+5],  S12, 0x4787C62A);
    c = FF(c, d, a, b, x[k+6],  S13, 0xA8304613);
    b = FF(b, c, d, a, x[k+7],  S14, 0xFD469501);
    a = FF(a, b, c, d, x[k+8],  S11, 0x698098D8);
    d = FF(d, a, b, c, x[k+9],  S12, 0x8B44F7AF);
    c = FF(c, d, a, b, x[k+10], S13, 0xFFFF5BB1);
    b = FF(b, c, d, a, x[k+11], S14, 0x895CD7BE);
    a = FF(a, b, c, d, x[k+12], S11, 0x6B901122);
    d = FF(d, a, b, c, x[k+13], S12, 0xFD987193);
    c = FF(c, d, a, b, x[k+14], S13, 0xA679438E);
    b = FF(b, c, d, a, x[k+15], S14, 0x49B40821);

    a = GG(a, b, c, d, x[k+1],  S21, 0xF61E2562);
    d = GG(d, a, b, c, x[k+6],  S22, 0xC040B340);
    c = GG(c, d, a, b, x[k+11], S23, 0x265E5A51);
    b = GG(b, c, d, a, x[k+0],  S24, 0xE9B6C7AA);
    a = GG(a, b, c, d, x[k+5],  S21, 0xD62F105D);
    d = GG(d, a, b, c, x[k+10], S22, 0x02441453);
    c = GG(c, d, a, b, x[k+15], S23, 0xD8A1E681);
    b = GG(b, c, d, a, x[k+4],  S24, 0xE7D3FBC8);
    a = GG(a, b, c, d, x[k+9],  S21, 0x21E1CDE6);
    d = GG(d, a, b, c, x[k+14], S22, 0xC33707D6);
    c = GG(c, d, a, b, x[k+3],  S23, 0xF4D50D87);
    b = GG(b, c, d, a, x[k+8],  S24, 0x455A14ED);
    a = GG(a, b, c, d, x[k+13], S21, 0xA9E3E905);
    d = GG(d, a, b, c, x[k+2],  S22, 0xFCEFA3F8);
    c = GG(c, d, a, b, x[k+7],  S23, 0x676F02D9);
    b = GG(b, c, d, a, x[k+12], S24, 0x8D2A4C8A);

    a = HH(a, b, c, d, x[k+5],  S31, 0xFFFA3942);
    d = HH(d, a, b, c, x[k+8],  S32, 0x8771F681);
    c = HH(c, d, a, b, x[k+11], S33, 0x6D9D6122);
    b = HH(b, c, d, a, x[k+14], S34, 0xFDE5380C);
    a = HH(a, b, c, d, x[k+1],  S31, 0xA4BEEA44);
    d = HH(d, a, b, c, x[k+4],  S32, 0x4BDECFA9);
    c = HH(c, d, a, b, x[k+7],  S33, 0xF6BB4B60);
    b = HH(b, c, d, a, x[k+10], S34, 0xBEBFBC70);
    a = HH(a, b, c, d, x[k+13], S31, 0x289B7EC6);
    d = HH(d, a, b, c, x[k+0],  S32, 0xEAA127FA);
    c = HH(c, d, a, b, x[k+3],  S33, 0xD4EF3085);
    b = HH(b, c, d, a, x[k+6],  S34, 0x04881D05);
    a = HH(a, b, c, d, x[k+9],  S31, 0xD9D4D039);
    d = HH(d, a, b, c, x[k+12], S32, 0xE6DB99E5);
    c = HH(c, d, a, b, x[k+15], S33, 0x1FA27CF8);
    b = HH(b, c, d, a, x[k+2],  S34, 0xC4AC5665);

    a = II(a, b, c, d, x[k+0],  S41, 0xF4292244);
    d = II(d, a, b, c, x[k+7],  S42, 0x432AFF97);
    c = II(c, d, a, b, x[k+14], S43, 0xAB9423A7);
    b = II(b, c, d, a, x[k+5],  S44, 0xFC93A039);
    a = II(a, b, c, d, x[k+12], S41, 0x655B59C3);
    d = II(d, a, b, c, x[k+3],  S42, 0x8F0CCC92);
    c = II(c, d, a, b, x[k+10], S43, 0xFFEFF47D);
    b = II(b, c, d, a, x[k+1],  S44, 0x85845DD1);
    a = II(a, b, c, d, x[k+8],  S41, 0x6FA87E4F);
    d = II(d, a, b, c, x[k+15], S42, 0xFE2CE6E0);
    c = II(c, d, a, b, x[k+6],  S43, 0xA3014314);
    b = II(b, c, d, a, x[k+13], S44, 0x4E0811A1);
    a = II(a, b, c, d, x[k+4],  S41, 0xF7537E82);
    d = II(d, a, b, c, x[k+11], S42, 0xBD3AF235);
    c = II(c, d, a, b, x[k+2],  S43, 0x2AD7D2BB);
    b = II(b, c, d, a, x[k+9],  S44, 0xEB86D391);

    a = (a + AA) & 0xffffffff;
    b = (b + BB) & 0xffffffff;
    c = (c + CC) & 0xffffffff;
    d = (d + DD) & 0xffffffff;
  }

  return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

// Defensive Security: Hash Type Identifier
export function identifyHash(hashStr: string): { possibleTypes: string[]; length: number; charset: string } {
  const clean = hashStr.trim();
  const len = clean.length;
  const isHex = /^[a-fA-F0-9]+$/.test(clean);
  const isBase64 = /^[a-zA-Z0-9+/=]+$/.test(clean);
  const possible: string[] = [];

  if (isHex) {
    if (len === 32) possible.push('MD5', 'NTLM', 'MD4');
    else if (len === 40) possible.push('SHA-1', 'RIPEMD-160');
    else if (len === 56) possible.push('SHA-224', 'SHA3-224');
    else if (len === 64) possible.push('SHA-256', 'BLAKE2s-256', 'SHA3-256');
    else if (len === 96) possible.push('SHA-384', 'SHA3-384');
    else if (len === 128) possible.push('SHA-512', 'BLAKE2b-512', 'Whirlpool');
    else if (len === 8) possible.push('CRC32');
    else if (len === 16) possible.push('MySQL 3.23', 'CRC64');
  } else if (clean.startsWith('$2a$') || clean.startsWith('$2b$') || clean.startsWith('$2y$')) {
    possible.push('bcrypt');
  } else if (clean.startsWith('$argon2id$') || clean.startsWith('$argon2i$')) {
    possible.push('Argon2');
  } else if (clean.startsWith('$6$')) {
    possible.push('SHA-512 Crypt (Linux shadow)');
  } else if (clean.startsWith('$5$')) {
    possible.push('SHA-256 Crypt (Linux shadow)');
  } else if (clean.startsWith('$1$')) {
    possible.push('MD5 Crypt');
  } else if (isBase64) {
    if (len === 44) possible.push('SHA-256 (Base64)');
    else if (len === 88) possible.push('SHA-512 (Base64)');
    else possible.push('Base64 Encoded String');
  }

  return {
    possibleTypes: possible.length > 0 ? possible : ['Unknown / Custom Hash'],
    length: len,
    charset: isHex ? 'Hexadecimal [0-9a-f]' : (isBase64 ? 'Base64 [a-zA-Z0-9+/=]' : 'Mixed/Modular Crypt')
  };
}

// Real Dictionary Hash Cracker (MD5, SHA1, SHA256)
const COMMON_WORDLIST = [
  'admin', 'password', '123456', '12345678', '123456789', 'qwerty', '111111', '12345', 'secret',
  'welcome', 'root', 'toor', 'matrix', 'atrix', 'cybersec', 'cybersec2026', 'hacker', 'dragon',
  'master', 'monkey', 'sunshine', 'princess', 'football', 'shadow', 'trustno1', 'iloveyou', 'pass123',
  'admin123', 'kali', 'test', 'login', 'server', 'database', 'codak', 'system', 'default', 'user',
  'guest', 'oracle', 'postgres', 'security', 'cisco', 'camera', 'terminal', 'access', 'hello',
  'letmein', 'mustang', 'superman', 'batman', 'starwars', 'killer', 'solo', 'michael', 'jordan',
  'chelsea', 'arsenal', 'barcelona', 'realmadrid', 'liverpool', 'indonesia', 'merdeka', 'jakarta',
  'bandung', 'surabaya', 'sayang', 'cinta', 'rahasia', 'bismillah', 'alhamdulillah', 'p@ssword',
  'P@ssw0rd', 'Admin@123', 'Password123', 'root123', 'kali2026', 'linux', 'ubuntu', 'archlinux'
];

export async function crackHashDictionary(targetHash: string): Promise<{ cracked: boolean; plaintext?: string; algorithm?: string; attempts: number; elapsedMs: number }> {
  const clean = targetHash.trim().toLowerCase();
  const startTime = performance.now();
  let attempts = 0;

  for (const word of COMMON_WORDLIST) {
    attempts++;
    // Check MD5
    if (clean.length === 32) {
      const md5Hash = md5(word).toLowerCase();
      if (md5Hash === clean) {
        return { cracked: true, plaintext: word, algorithm: 'MD5', attempts, elapsedMs: Math.round(performance.now() - startTime) };
      }
    }

    // Check SHA-1
    if (clean.length === 40) {
      const sha1Hash = await computeHash('SHA-1', word);
      if (sha1Hash.toLowerCase() === clean) {
        return { cracked: true, plaintext: word, algorithm: 'SHA-1', attempts, elapsedMs: Math.round(performance.now() - startTime) };
      }
    }

    // Check SHA-256
    if (clean.length === 64) {
      const sha256Hash = await computeHash('SHA-256', word);
      if (sha256Hash.toLowerCase() === clean) {
        return { cracked: true, plaintext: word, algorithm: 'SHA-256', attempts, elapsedMs: Math.round(performance.now() - startTime) };
      }
    }
  }

  return { cracked: false, attempts, elapsedMs: Math.round(performance.now() - startTime) };
}

