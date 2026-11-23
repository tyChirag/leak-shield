import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createLeakShieldStream } from '../src/index.js';

test('createLeakShieldStream transforms and redacts data in streams', async () => {
  const shieldStream = createLeakShieldStream();
  const chunks: Buffer[] = [];

  const readable = Readable.from([
    'Sending request with token: sk-proj-1234567890abcdef1234567890\n',
    'And header: Bearer myTokenSecretValue123\n',
  ]);

  await new Promise<void>((resolve, reject) => {
    readable
      .pipe(shieldStream)
      .on('data', (chunk) => chunks.push(chunk))
      .on('end', () => resolve())
      .on('error', reject);
  });

  const output = Buffer.concat(chunks).toString('utf8');
  assert.ok(!output.includes('sk-proj-1234567890'));
  assert.ok(!output.includes('myTokenSecretValue123'));
  assert.ok(output.includes('[REDACTED]'));
});
