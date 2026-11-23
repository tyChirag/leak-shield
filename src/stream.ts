import { Transform, TransformCallback } from 'node:stream';
import { LeakShield } from './redactor.js';
import { StreamShieldOptions } from './types.js';

/**
 * Creates a Node.js Transform Stream that redacts secrets from passing chunks.
 * Perfect for piping to process.stdout or log file write streams.
 */
export function createLeakShieldStream(options: StreamShieldOptions = {}): Transform {
  const shield = new LeakShield(options);
  const encoding = options.encoding || 'utf8';

  return new Transform({
    transform(chunk: Buffer | string, _enc: BufferEncoding, callback: TransformCallback) {
      try {
        const text = typeof chunk === 'string' ? chunk : chunk.toString(encoding);
        const redacted = shield.redact(text);
        callback(null, Buffer.from(redacted, encoding));
      } catch (err) {
        callback(err as Error);
      }
    },
  });
}
