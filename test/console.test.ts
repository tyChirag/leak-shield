import test from 'node:test';
import assert from 'node:assert/strict';
import { patchConsole, leakShield } from '../src/index.js';

test('patchConsole intercepts console methods and unpatches cleanly', () => {
  const captured: unknown[][] = [];
  const originalLog = console.log;

  // Intercept raw output
  console.log = (...args: unknown[]) => {
    captured.push(args);
  };

  const unpatch = patchConsole(leakShield, ['log']);

  try {
    console.log('Secret key is:', 'sk-proj-1234567890abcdef1234567890');
    console.log({ user: 'bob', password: 'plainPassword123!' });

    assert.equal(captured.length, 2);
    assert.equal(captured[0][1], '[REDACTED]');
    assert.deepEqual(captured[1][0], { user: 'bob', password: '[REDACTED]' });
  } finally {
    unpatch();
    console.log = originalLog;
  }
});
