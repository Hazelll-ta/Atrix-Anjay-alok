export type FileType = 'file' | 'dir';

export interface FSItem {
  name: string;
  type: FileType;
  content?: string;
  size?: number;
  permissions?: string;
  modified: string;
  children?: { [name: string]: FSItem };
}

export interface NeofetchInfo {
  userHost: string;
  os: string;
  host: string;
  kernel: string;
  uptime: string;
  packages: string;
  shell: string;
  terminal: string;
  cpu: string;
  memory: string;
  swap: string;
  localIp: string;
  battery: string;
  locale: string;
}

export interface TerminalOutputLine {
  id: string;
  type: 'output' | 'input' | 'error' | 'ascii' | 'progress' | 'system' | 'logo' | 'neofetch';
  content: string;
  prompt?: string;
  timestamp?: number;
  color?: string;
  neofetchData?: NeofetchInfo;
}

export interface RunningProcess {
  pid: number;
  user: string;
  pr: number;
  ni: number;
  virt: string;
  res: string;
  shr: string;
  status: 'S' | 'R' | 'Z';
  cpu: number;
  mem: number;
  time: string;
  command: string;
}
