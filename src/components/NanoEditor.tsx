import { useState, useEffect, useRef } from 'react';
import { vfs } from '../utils/virtualFileSystem';

interface NanoEditorProps {
  filePath: string;
  initialContent: string;
  onExit: (message?: string) => void;
}

export function NanoEditor({ filePath, initialContent, onExit }: NanoEditorProps) {
  const [content, setContent] = useState(initialContent);
  const [isModified, setIsModified] = useState(false);
  const [statusMsg, setStatusMsg] = useState('Type text. Press Ctrl+O to Save, Ctrl+X to Exit.');
  const [showExitConfirm, setShowExitConfirm] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.focus();
    }
  }, []);

  const handleSave = () => {
    try {
      vfs.writeFile(filePath, content);
      setIsModified(false);
      const lines = content.split('\n').length;
      setStatusMsg(`[ Wrote ${lines} lines to ${filePath} ]`);
      setTimeout(() => setStatusMsg('Type text. Press Ctrl+O to Save, Ctrl+X to Exit.'), 2000);
    } catch (err: any) {
      setStatusMsg(`[ Error writing file: ${err.message} ]`);
    }
  };

  const handleExit = () => {
    if (isModified) {
      setShowExitConfirm(true);
      setStatusMsg('Save modified buffer? (Y to Save & Exit, N to Discard, Esc to Cancel)');
    } else {
      onExit('Exited nano');
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    // Save: Ctrl+O or Ctrl+S
    if ((e.ctrlKey && e.key === 'o') || (e.ctrlKey && e.key === 's')) {
      e.preventDefault();
      handleSave();
      return;
    }
    // Exit: Ctrl+X
    if (e.ctrlKey && e.key === 'x') {
      e.preventDefault();
      handleExit();
      return;
    }
    // Tab key inserts 2 spaces
    if (e.key === 'Tab') {
      e.preventDefault();
      const target = e.currentTarget;
      const start = target.selectionStart;
      const end = target.selectionEnd;
      const newText = content.substring(0, start) + '  ' + content.substring(end);
      setContent(newText);
      setIsModified(true);
      setTimeout(() => {
        target.selectionStart = target.selectionEnd = start + 2;
      }, 0);
      return;
    }

    if (showExitConfirm) {
      if (e.key.toLowerCase() === 'y') {
        e.preventDefault();
        handleSave();
        onExit(`File ${filePath} saved and closed.`);
      } else if (e.key.toLowerCase() === 'n') {
        e.preventDefault();
        onExit('Changes discarded.');
      } else if (e.key === 'Escape') {
        e.preventDefault();
        setShowExitConfirm(false);
        setStatusMsg('Cancelled exit.');
      }
    }
  };

  const lines = content.split('\n');
  const lineCount = lines.length;

  return (
    <div className="flex flex-col h-[85vh] bg-black text-white font-mono border border-white/20 p-2 my-2 select-none">
      {/* Nano Header */}
      <div className="bg-white text-black px-2 py-0.5 flex justify-between text-xs font-bold">
        <span>GNU nano 7.2</span>
        <span>File: {filePath}</span>
        <span>{isModified ? '[Modified]' : ''}</span>
      </div>

      {/* Editor Body */}
      <div className="flex-1 flex overflow-hidden my-2 border border-white/10 bg-black">
        {/* Line Numbers */}
        <div className="text-white/40 text-xs px-2 py-2 select-none text-right border-r border-white/10 font-mono">
          {lines.map((_, i) => (
            <div key={i}>{i + 1}</div>
          ))}
        </div>

        {/* Text Area */}
        <textarea
          ref={textareaRef}
          value={content}
          onChange={(e) => {
            setContent(e.target.value);
            setIsModified(true);
          }}
          onKeyDown={handleKeyDown}
          className="flex-1 bg-transparent text-white p-2 text-xs md:text-sm font-mono resize-none outline-none leading-relaxed overflow-auto"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
        />
      </div>

      {/* Status Bar */}
      <div className="bg-white/10 text-white text-xs px-2 py-1 mb-1 flex justify-between items-center">
        <span>{statusMsg}</span>
        <span className="text-white/60">{lineCount} lines</span>
      </div>

      {/* Shortcut Menu */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-1 text-[11px] bg-white/5 p-1 border-t border-white/20">
        <button
          onClick={handleSave}
          className="bg-white/10 hover:bg-white hover:text-black px-2 py-1 text-left flex items-center justify-between cursor-pointer transition-colors"
        >
          <span className="font-bold">^O</span>
          <span>Save (WriteOut)</span>
        </button>
        <button
          onClick={handleExit}
          className="bg-white/10 hover:bg-white hover:text-black px-2 py-1 text-left flex items-center justify-between cursor-pointer transition-colors"
        >
          <span className="font-bold">^X</span>
          <span>Exit</span>
        </button>
        <button
          onClick={() => {
            setContent('');
            setIsModified(true);
          }}
          className="bg-white/10 hover:bg-white hover:text-black px-2 py-1 text-left flex items-center justify-between cursor-pointer transition-colors"
        >
          <span className="font-bold">^K</span>
          <span>Clear All</span>
        </button>
        <button
          onClick={() => onExit('Nano closed.')}
          className="bg-white/10 hover:bg-white hover:text-black px-2 py-1 text-left flex items-center justify-between cursor-pointer transition-colors"
        >
          <span className="font-bold">Esc</span>
          <span>Close</span>
        </button>
      </div>
    </div>
  );
}
