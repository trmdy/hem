import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { registerSensitive } from './log';

/**
 * Concealed clipboard write on macOS: a JXA helper adds the
 * org.nspasteboard.ConcealedType flavor alongside the plain string so
 * clipboard managers skip it. The value travels over stdin — never argv,
 * env, or disk. (Ported from hem-raycast, which used Raycast's native
 * concealed copy; Electron's clipboard API has no concealed flavor.)
 */
const JXA_CONCEALED_COPY = `
ObjC.import('AppKit');
function run() {
  var data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
  var str = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding);
  var pb = $.NSPasteboard.generalPasteboard;
  pb.clearContents;
  pb.setStringForType(str, 'org.nspasteboard.ConcealedType');
  pb.setStringForType(str, $.NSPasteboardTypeString);
}
`;

export interface ClipboardAdapter {
  copyConcealed(value: string): Promise<void>;
  copyPlain(text: string): Promise<void>;
  scheduleClear(value: string, seconds: number): void;
}

function runOsascriptConcealed(value: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/osascript', ['-l', 'JavaScript', '-e', JXA_CONCEALED_COPY], {
      stdio: ['pipe', 'ignore', 'ignore'],
    });
    child.on('error', reject);
    child.on('exit', (code) =>
      code === 0 ? resolve() : reject(new Error(`osascript concealed copy exited ${code}`)),
    );
    child.stdin.write(value, 'utf8');
    child.stdin.end();
  });
}

/**
 * Schedule a clipboard clear in a detached helper so it survives app quit.
 * The clipboard is only cleared if it still holds the copied value; the
 * comparison uses a SHA-256 passed via stdin, so the value itself never
 * touches argv, env, or disk.
 */
export function scheduleClipboardClear(value: string, seconds: number): void {
  if (!Number.isFinite(seconds) || seconds <= 0) return;
  const hash = createHash('sha256').update(value, 'utf8').digest('hex');
  const script = [
    'IFS= read -r h',
    `sleep ${Math.floor(seconds)}`,
    `cur=$(/usr/bin/pbpaste 2>/dev/null | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')`,
    `if [ "$cur" = "$h" ]; then printf '' | /usr/bin/pbcopy; fi`,
  ].join('; ');
  const child = spawn('/bin/sh', ['-c', script], {
    detached: true,
    stdio: ['pipe', 'ignore', 'ignore'],
  });
  child.stdin.write(`${hash}\n`);
  child.stdin.end();
  child.unref();
}

/** Production adapter. Plain copies go through Electron's clipboard. */
export function createDarwinClipboard(
  electronClipboard: { writeText(text: string): void },
): ClipboardAdapter {
  return {
    async copyConcealed(value: string): Promise<void> {
      registerSensitive(value);
      try {
        await runOsascriptConcealed(value);
      } catch {
        // Concealment is best-effort hardening; the copy itself must work.
        electronClipboard.writeText(value);
      }
    },
    async copyPlain(text: string): Promise<void> {
      electronClipboard.writeText(text);
    },
    scheduleClear: scheduleClipboardClear,
  };
}
