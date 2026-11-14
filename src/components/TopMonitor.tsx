import { useState, useEffect } from 'react';
import { RunningProcess } from '../types/terminal';

interface TopMonitorProps {
  onExit: () => void;
}

const initialProcesses: RunningProcess[] = [
  { pid: 1, user: 'root', pr: 20, ni: 0, virt: '168.2M', res: '11.2M', shr: '7.1M', status: 'S', cpu: 0.1, mem: 0.4, time: '0:01.42', command: 'systemd' },
  { pid: 42, user: 'root', pr: 20, ni: 0, virt: '420.5M', res: '64.1M', shr: '38.2M', status: 'S', cpu: 2.4, mem: 2.1, time: '1:12.80', command: 'atrix-core' },
  { pid: 108, user: 'root', pr: 20, ni: 0, virt: '84.0M', res: '9.4M', shr: '4.8M', status: 'S', cpu: 0.0, mem: 0.3, time: '0:00.12', command: 'vfs-daemon' },
  { pid: 219, user: 'root', pr: 20, ni: 0, virt: '112.3M', res: '14.8M', shr: '8.2M', status: 'S', cpu: 0.8, mem: 0.5, time: '0:05.19', command: 'net-service' },
  { pid: 1337, user: 'user', pr: 20, ni: 0, virt: '52.1M', res: '18.3M', shr: '12.0M', status: 'R', cpu: 4.8, mem: 1.2, time: '0:03.45', command: 'top' },
  { pid: 912, user: 'user', pr: 20, ni: 0, virt: '24.2M', res: '6.1M', shr: '3.4M', status: 'S', cpu: 0.0, mem: 0.2, time: '0:00.67', command: 'zsh' },
  { pid: 2048, user: 'user', pr: 20, ni: 0, virt: '280.0M', res: '48.2M', shr: '22.1M', status: 'S', cpu: 1.2, mem: 1.6, time: '0:09.30', command: 'node-worker' }
];

export function TopMonitor({ onExit }: TopMonitorProps) {
  const [processes, setProcesses] = useState<RunningProcess[]>(initialProcesses);
  const [cpuUsage, setCpuUsage] = useState(12.5);
  const [memUsage, setMemUsage] = useState(48.2);
  const [killPidInput, setKillPidInput] = useState('');
  const [statusMsg, setStatusMsg] = useState('Press [q] to quit, or enter PID to terminate.');

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === 'q' || e.key === 'Escape') {
        onExit();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onExit]);

  useEffect(() => {
    const interval = setInterval(() => {
      // Fluctuate CPU slightly
      const newCpu = Math.min(99, Math.max(3, +(Math.random() * 20 + 8).toFixed(1)));
      setCpuUsage(newCpu);

      setProcesses(prev =>
        prev.map(p => {
          if (p.command === 'top') {
            return { ...p, cpu: +(Math.random() * 2 + 3).toFixed(1) };
          }
          if (p.command === 'atrix-core') {
            return { ...p, cpu: +(Math.random() * 4 + 1).toFixed(1) };
          }
          return p;
        })
      );
    }, 1200);

    return () => clearInterval(interval);
  }, []);

  const handleKill = (pidToKill: number) => {
    if (pidToKill === 1) {
      setStatusMsg('Cannot kill init system (PID 1)');
      return;
    }
    setProcesses(prev => prev.filter(p => p.pid !== pidToKill));
    setStatusMsg(`Process ${pidToKill} terminated.`);
    setKillPidInput('');
  };

  const cpuBlocks = Math.round((cpuUsage / 100) * 40);
  const memBlocks = Math.round((memUsage / 100) * 40);

  return (
    <div className="bg-black text-white font-mono border border-white/20 p-3 my-2 select-none">
      {/* Top Header */}
      <div className="flex justify-between items-center border-b border-white/20 pb-2 mb-2 text-xs">
        <div>
          <span className="text-white font-bold">ATRIX OS TOP</span> - Tasks: {processes.length} total, 1 running, {processes.length - 1} sleeping
        </div>
        <button
          onClick={onExit}
          className="bg-white text-black px-2 py-0.5 text-xs font-bold hover:bg-white/80 cursor-pointer"
        >
          [q] Quit
        </button>
      </div>

      {/* Resource Meters */}
      <div className="text-xs space-y-1 mb-3">
        <div>
          CPU  [{'|'.repeat(cpuBlocks)}{' '.repeat(40 - cpuBlocks)}] {cpuUsage.toFixed(1)}%
        </div>
        <div>
          MEM  [{'|'.repeat(memBlocks)}{' '.repeat(40 - memBlocks)}] {memUsage.toFixed(1)}% (1974MB / 4096MB)
        </div>
        <div>
          SWP  [{' '.repeat(40)}] 0.0% (0MB / 2048MB)
        </div>
      </div>

      {/* Process Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="bg-white text-black font-bold">
              <th className="p-1">PID</th>
              <th className="p-1">USER</th>
              <th className="p-1">PR</th>
              <th className="p-1">VIRT</th>
              <th className="p-1">RES</th>
              <th className="p-1">S</th>
              <th className="p-1">%CPU</th>
              <th className="p-1">%MEM</th>
              <th className="p-1">TIME+</th>
              <th className="p-1">COMMAND</th>
              <th className="p-1 text-right">ACTION</th>
            </tr>
          </thead>
          <tbody>
            {processes.map((proc) => (
              <tr key={proc.pid} className="hover:bg-white/10 border-b border-white/5">
                <td className="p-1">{proc.pid}</td>
                <td className="p-1">{proc.user}</td>
                <td className="p-1">{proc.pr}</td>
                <td className="p-1">{proc.virt}</td>
                <td className="p-1">{proc.res}</td>
                <td className="p-1">{proc.status}</td>
                <td className="p-1">{proc.cpu}%</td>
                <td className="p-1">{proc.mem}%</td>
                <td className="p-1">{proc.time}</td>
                <td className="p-1 font-semibold">{proc.command}</td>
                <td className="p-1 text-right">
                  {proc.pid !== 1 && (
                    <button
                      onClick={() => handleKill(proc.pid)}
                      className="text-[10px] text-white/70 hover:text-white underline cursor-pointer"
                    >
                      kill
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Kill Bar & Quick Action */}
      <div className="mt-3 pt-2 border-t border-white/20 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="text-white/70">{statusMsg}</div>
        <div className="flex items-center gap-2">
          <span>Kill PID:</span>
          <input
            type="number"
            value={killPidInput}
            onChange={(e) => setKillPidInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && killPidInput) {
                handleKill(parseInt(killPidInput));
              }
            }}
            placeholder="PID"
            className="w-16 bg-black border border-white/40 px-1 py-0.5 text-xs text-white"
          />
          <button
            onClick={() => killPidInput && handleKill(parseInt(killPidInput))}
            className="bg-white/20 hover:bg-white hover:text-black px-2 py-0.5 text-xs cursor-pointer"
          >
            Send SIGTERM
          </button>
        </div>
      </div>
    </div>
  );
}
