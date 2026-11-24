/**
 * The only log sink in the main process — everything that wants to log goes
 * through here, and everything that ever touches a plaintext secret value
 * registers it first. Registered strings are scrubbed from every message
 * before it reaches stdout/stderr, so a stray error containing a value can't
 * leak it. The redaction unit test asserts this property.
 */

const MAX_TRACKED = 256;

/** Insertion-ordered so the oldest registrations fall off first. */
const sensitive: string[] = [];
const sensitiveSet = new Set<string>();

export function registerSensitive(value: string): void {
  if (!value || value.length < 4) return; // scrubbing 1–3 char strings would shred messages
  if (sensitiveSet.has(value)) return;
  sensitive.push(value);
  sensitiveSet.add(value);
  while (sensitive.length > MAX_TRACKED) {
    const dropped = sensitive.shift();
    if (dropped !== undefined) sensitiveSet.delete(dropped);
  }
}

export function scrub(text: string): string {
  let out = text;
  for (const value of sensitive) {
    if (out.includes(value)) {
      out = out.split(value).join('[redacted]');
    }
  }
  return out;
}

function serialize(parts: unknown[]): string {
  return parts
    .map((p) => {
      if (typeof p === 'string') return p;
      if (p instanceof Error) return `${p.name}: ${p.message}`;
      try {
        return JSON.stringify(p);
      } catch {
        return String(p);
      }
    })
    .join(' ');
}

type Sink = (line: string) => void;

let infoSink: Sink = (line) => console.log(line);
let errorSink: Sink = (line) => console.error(line);

/** Test seam: capture the scrubbed output. */
export function setSinks(info: Sink, error: Sink): void {
  infoSink = info;
  errorSink = error;
}

export function logInfo(...parts: unknown[]): void {
  infoSink(scrub(serialize(parts)));
}

export function logError(...parts: unknown[]): void {
  errorSink(scrub(serialize(parts)));
}
