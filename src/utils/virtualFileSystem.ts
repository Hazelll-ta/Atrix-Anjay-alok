import { FSItem } from '../types/terminal';

const FS_STORAGE_KEY = 'atrix_vfs_v1';

const defaultFS: FSItem = {
  name: '',
  type: 'dir',
  modified: new Date().toISOString(),
  permissions: 'drwxr-xr-x',
  children: {
    home: {
      name: 'home',
      type: 'dir',
      modified: new Date().toISOString(),
      permissions: 'drwxr-xr-x',
      children: {
        user: {
          name: 'user',
          type: 'dir',
          modified: new Date().toISOString(),
          permissions: 'drwxr-xr-x',
          children: {
            'README.md': {
              name: 'README.md',
              type: 'file',
              modified: new Date().toISOString(),
              permissions: '-rw-r--r--',
              content: `# ATRIX System Toolkit & Terminal

Selamat datang di terminal web beneran yang bekerja tanpa install apapun!

### Real Tools Tersedia:
- File System: ls, cd, pwd, cat, touch, mkdir, rm, cp, mv, nano/edit, tree, grep, find
- Network Tools: curl (real HTTP), ping (real latency), dns (real records), ip, speedtest, weather
- Dev & Security: js / node (real JS runner), calc, hash (sha256/md5), base64, jwt decoder, uuid, diff
- System & Monitor: top / htop (live task manager), ps, kill, neofetch, uptime, date
- Fun & Visual: matrix (digital rain), cowsay, fortune, menu
- AI Assistant: ai <pertanyaan> (Gemini engine)

Ketik 'help' untuk daftar lengkap perintah.
`
            },
            'notes.txt': {
              name: 'notes.txt',
              type: 'file',
              modified: new Date().toISOString(),
              permissions: '-rw-r--r--',
              content: `Agenda & Todo:
1. Jalankan 'speedtest' untuk cek koneksi internet
2. Coba 'curl https://api.github.com/zen'
3. Tes 'weather Jakarta' atau 'weather Tokyo'
4. Edit file ini dengan perintah: nano notes.txt
`
            },
            projects: {
              name: 'projects',
              type: 'dir',
              modified: new Date().toISOString(),
              permissions: 'drwxr-xr-x',
              children: {
                'demo.js': {
                  name: 'demo.js',
                  type: 'file',
                  modified: new Date().toISOString(),
                  permissions: '-rw-r--r--',
                  content: `// Jalankan script ini dengan: run demo.js
function fibonacci(n) {
  const seq = [0, 1];
  for (let i = 2; i < n; i++) {
    seq.push(seq[i-1] + seq[i-2]);
  }
  return seq;
}

console.log("Fibonacci 10 angka pertama:");
console.log(fibonacci(10).join(", "));
console.log("Waktu sekarang:", new Date().toLocaleTimeString());
`
                },
                'calc_pi.js': {
                  name: 'calc_pi.js',
                  type: 'file',
                  modified: new Date().toISOString(),
                  permissions: '-rw-r--r--',
                  content: `// Leibniz formula for Pi
let pi = 0;
let n = 100000;
for (let i = 0; i < n; i++) {
  pi += (i % 2 === 0 ? 1 : -1) / (2 * i + 1);
}
pi *= 4;
console.log("Estimasi Pi (" + n + " iterasi):", pi);
console.log("Math.PI sesungguhnya:", Math.PI);
`
                }
              }
            }
          }
        }
      }
    },
    etc: {
      name: 'etc',
      type: 'dir',
      modified: new Date().toISOString(),
      permissions: 'drwxr-xr-x',
      children: {
        hostname: {
          name: 'hostname',
          type: 'file',
          modified: new Date().toISOString(),
          permissions: '-rw-r--r--',
          content: 'atrix-system\n'
        },
        'os-release': {
          name: 'os-release',
          type: 'file',
          modified: new Date().toISOString(),
          permissions: '-rw-r--r--',
          content: 'NAME="ATRIX OS"\nVERSION="2026.1 (Matrix Rolling)"\nID=atrix\nID_LIKE=arch\nPRETTY_NAME="ATRIX OS x86_64"\n'
        },
        motd: {
          name: 'motd',
          type: 'file',
          modified: new Date().toISOString(),
          permissions: '-rw-r--r--',
          content: 'Welcome to ATRIX OS - System Toolkit Terminal.\nAll utilities are functional and live.\n'
        }
      }
    },
    bin: {
      name: 'bin',
      type: 'dir',
      modified: new Date().toISOString(),
      permissions: 'drwxr-xr-x',
      children: {
        ls: { name: 'ls', type: 'file', modified: new Date().toISOString(), permissions: '-rwxr-xr-x', content: '#!/bin/sh\n' },
        cat: { name: 'cat', type: 'file', modified: new Date().toISOString(), permissions: '-rwxr-xr-x', content: '#!/bin/sh\n' },
        nano: { name: 'nano', type: 'file', modified: new Date().toISOString(), permissions: '-rwxr-xr-x', content: '#!/bin/sh\n' },
        curl: { name: 'curl', type: 'file', modified: new Date().toISOString(), permissions: '-rwxr-xr-x', content: '#!/bin/sh\n' },
        ping: { name: 'ping', type: 'file', modified: new Date().toISOString(), permissions: '-rwxr-xr-x', content: '#!/bin/sh\n' },
        speedtest: { name: 'speedtest', type: 'file', modified: new Date().toISOString(), permissions: '-rwxr-xr-x', content: '#!/bin/sh\n' },
        'challenge.elf': {
          name: 'challenge.elf',
          type: 'file',
          modified: new Date().toISOString(),
          permissions: '-rwxr-xr-x',
          content: '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00\nDEBUG_FLAG: CTF{str1ngs_c0mm4nd_f7w_2026}\nLicense verification module\nGCC 11.4.0\n'
        }
      }
    },
    var: {
      name: 'var',
      type: 'dir',
      modified: new Date().toISOString(),
      permissions: 'drwxr-xr-x',
      children: {
        log: {
          name: 'log',
          type: 'dir',
          modified: new Date().toISOString(),
          permissions: 'drwxr-xr-x',
          children: {
            'system.log': {
              name: 'system.log',
              type: 'file',
              modified: new Date().toISOString(),
              permissions: '-rw-r--r--',
              content: '[INFO] Kernel initialized successfully.\n[INFO] Virtual VFS mounted at /\n[INFO] Real network adapter initialized.\n'
            }
          }
        }
      }
    },
    tmp: {
      name: 'tmp',
      type: 'dir',
      modified: new Date().toISOString(),
      permissions: 'drwxrwxrwt',
      children: {}
    }
  }
};

class VirtualFileSystem {
  private root: FSItem;

  constructor() {
    this.root = this.loadFS();
  }

  private loadFS(): FSItem {
    try {
      const saved = localStorage.getItem(FS_STORAGE_KEY);
      if (saved) {
        return JSON.parse(saved);
      }
    } catch {
      // fallback
    }
    return JSON.parse(JSON.stringify(defaultFS));
  }

  public saveFS(): void {
    try {
      localStorage.setItem(FS_STORAGE_KEY, JSON.stringify(this.root));
    } catch {
      // storage quota or disabled
    }
  }

  public resetFS(): void {
    this.root = JSON.parse(JSON.stringify(defaultFS));
    this.saveFS();
  }

  // Normalize path string
  public normalizePath(path: string, currentDir: string): string {
    let target = path.trim();
    if (target.startsWith('~')) {
      target = target.replace(/^~/, '/home/user');
    }
    if (!target.startsWith('/')) {
      target = currentDir === '/' ? `/${target}` : `${currentDir}/${target}`;
    }

    const segments = target.split('/').filter(Boolean);
    const resolved: string[] = [];

    for (const seg of segments) {
      if (seg === '.') continue;
      if (seg === '..') {
        if (resolved.length > 0) resolved.pop();
      } else {
        resolved.push(seg);
      }
    }

    return '/' + resolved.join('/');
  }

  public getItem(absolutePath: string): FSItem | null {
    if (absolutePath === '/') return this.root;
    const parts = absolutePath.split('/').filter(Boolean);
    let current = this.root;

    for (const part of parts) {
      if (!current.children || !current.children[part]) {
        return null;
      }
      current = current.children[part];
    }

    return current;
  }

  public listDirectory(absolutePath: string): FSItem[] {
    const item = this.getItem(absolutePath);
    if (!item || item.type !== 'dir' || !item.children) {
      return [];
    }
    return Object.values(item.children);
  }

  public createFile(absolutePath: string, content = ''): boolean {
    const parts = absolutePath.split('/').filter(Boolean);
    if (parts.length === 0) return false;
    const fileName = parts.pop()!;
    const parentPath = '/' + parts.join('/');
    const parent = this.getItem(parentPath);

    if (!parent || parent.type !== 'dir') return false;
    if (!parent.children) parent.children = {};

    parent.children[fileName] = {
      name: fileName,
      type: 'file',
      content,
      size: content.length,
      modified: new Date().toISOString(),
      permissions: '-rw-r--r--'
    };

    this.saveFS();
    return true;
  }

  public createFileRecursive(absolutePath: string, content = ''): boolean {
    const parts = absolutePath.split('/').filter(Boolean);
    if (parts.length === 0) return false;
    
    let current = this.root;
    let accumulatedPath = '';

    for (let i = 0; i < parts.length - 1; i++) {
      const dirName = parts[i];
      accumulatedPath += '/' + dirName;
      if (!current.children) current.children = {};
      if (!current.children[dirName] || current.children[dirName].type !== 'dir') {
        current.children[dirName] = {
          name: dirName,
          type: 'dir',
          modified: new Date().toISOString(),
          permissions: 'drwxr-xr-x',
          children: {}
        };
      }
      current = current.children[dirName];
    }

    const fileName = parts[parts.length - 1];
    if (!current.children) current.children = {};
    current.children[fileName] = {
      name: fileName,
      type: 'file',
      content,
      size: content.length,
      modified: new Date().toISOString(),
      permissions: '-rw-r--r--'
    };

    this.saveFS();
    return true;
  }

  public createDirectory(absolutePath: string): boolean {
    const parts = absolutePath.split('/').filter(Boolean);
    if (parts.length === 0) return false;
    const dirName = parts.pop()!;
    const parentPath = '/' + parts.join('/');
    const parent = this.getItem(parentPath);

    if (!parent || parent.type !== 'dir') return false;
    if (!parent.children) parent.children = {};

    if (parent.children[dirName]) {
      return false; // already exists
    }

    parent.children[dirName] = {
      name: dirName,
      type: 'dir',
      modified: new Date().toISOString(),
      permissions: 'drwxr-xr-x',
      children: {}
    };

    this.saveFS();
    return true;
  }

  public writeFile(absolutePath: string, content: string, append = false): boolean {
    const item = this.getItem(absolutePath);
    if (item && item.type === 'file') {
      item.content = append ? (item.content || '') + content : content;
      item.size = (item.content || '').length;
      item.modified = new Date().toISOString();
      this.saveFS();
      return true;
    }
    return this.createFile(absolutePath, content);
  }

  public deleteItem(absolutePath: string, recursive = false): boolean {
    if (absolutePath === '/' || absolutePath === '') return false;
    const parts = absolutePath.split('/').filter(Boolean);
    const itemName = parts.pop()!;
    const parentPath = '/' + parts.join('/');
    const parent = this.getItem(parentPath);

    if (!parent || !parent.children || !parent.children[itemName]) return false;

    const target = parent.children[itemName];
    if (target.type === 'dir' && Object.keys(target.children || {}).length > 0 && !recursive) {
      return false; // directory not empty
    }

    delete parent.children[itemName];
    this.saveFS();
    return true;
  }

  public copyItem(srcPath: string, destPath: string): boolean {
    const src = this.getItem(srcPath);
    if (!src) return false;

    let targetPath = destPath;
    const dest = this.getItem(destPath);
    if (dest && dest.type === 'dir') {
      targetPath = destPath === '/' ? `/${src.name}` : `${destPath}/${src.name}`;
    }

    const parts = targetPath.split('/').filter(Boolean);
    const newName = parts.pop()!;
    const parentPath = '/' + parts.join('/');
    const parent = this.getItem(parentPath);

    if (!parent || parent.type !== 'dir') return false;
    if (!parent.children) parent.children = {};

    const copyObj = JSON.parse(JSON.stringify(src));
    copyObj.name = newName;
    copyObj.modified = new Date().toISOString();
    parent.children[newName] = copyObj;

    this.saveFS();
    return true;
  }

  public moveItem(srcPath: string, destPath: string): boolean {
    if (this.copyItem(srcPath, destPath)) {
      return this.deleteItem(srcPath, true);
    }
    return false;
  }

  public renderTree(startPath: string, prefix = '', isLast = true): string[] {
    const item = this.getItem(startPath);
    if (!item) return ['Directory not found'];

    const lines: string[] = [];
    if (prefix === '') {
      lines.push(item.name || '/');
    }

    if (item.type === 'dir' && item.children) {
      const keys = Object.keys(item.children).sort();
      keys.forEach((key, index) => {
        const child = item.children![key];
        const lastChild = index === keys.length - 1;
        const branch = lastChild ? '└── ' : '├── ';
        const childPrefix = prefix + (isLast && prefix !== '' ? '    ' : '│   ');
        
        lines.push(`${prefix}${branch}${child.name}${child.type === 'dir' ? '/' : ''}`);
        if (child.type === 'dir') {
          const subLines = this.renderTree(`${startPath === '/' ? '' : startPath}/${child.name}`, childPrefix, lastChild);
          // remove first line since it was just the child name
          subLines.shift();
          lines.push(...subLines);
        }
      });
    }

    return lines;
  }
}

export const vfs = new VirtualFileSystem();
