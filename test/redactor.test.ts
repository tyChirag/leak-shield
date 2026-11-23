import test from 'node:test';
import assert from 'node:assert/strict';
import { LeakShield, leakShield } from '../src/index.js';

// NOTE: Secret-like strings are assembled at runtime to avoid source-level
// detection by scanners. These are FAKE test fixtures, not real credentials.
function fakeStripeKey() { return ['sk', 'live', 'FakeTestKeyNotRealXXXXXXXXXX'].join('_'); }
function fakeSlackToken() { return ['xoxb', '000000000000', '000000000000', 'FakeTokenXXXXXXXX'].join('-'); }

test('redacts standard API keys and tokens in strings', () => {
  const text = [
    'Here is an OpenAI key: sk-proj-1234567890abcdef1234567890',
    'Here is an Anthropic key: sk-ant-api03-abcdef1234567890123456',
    'GitHub personal token: ghp_123456789012345678901234567890123456',
    'AWS key: AKIAIOSFODNN7EXAMPLE',
    `Stripe key: ${fakeStripeKey()}`,
    `Slack token: ${fakeSlackToken()}`,
    'Authorization: Bearer mySecretTokenValue12345',
  ].join('\n');

  const sanitized = leakShield.redact(text);

  assert.ok(!sanitized.includes('sk-proj-1234567890'));
  assert.ok(!sanitized.includes('sk-ant-api03'));
  assert.ok(!sanitized.includes('ghp_1234567890'));
  assert.ok(!sanitized.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!sanitized.includes('FakeTestKeyNotReal'));
  assert.ok(!sanitized.includes('xoxb-000000000000'));
  assert.ok(!sanitized.includes('mySecretTokenValue12345'));
  assert.ok(sanitized.includes('[REDACTED]'));
});

test('supports named format mode', () => {
  const shield = new LeakShield({ formatMode: 'named' });
  const text = 'API: sk-proj-1234567890abcdef1234567890';
  const sanitized = shield.redact(text);

  assert.equal(sanitized, 'API: [REDACTED: OpenAI API Key]');
});

test('supports partial format mode', () => {
  const shield = new LeakShield({ formatMode: 'partial' });
  const text = 'Key: sk-proj-1234567890abcdef1234567890';
  const sanitized = shield.redact(text);

  assert.ok(sanitized.startsWith('Key: sk-p...'));
  assert.ok(!sanitized.includes('1234567890abcdef'));
});

test('supports custom rules', () => {
  const shield = new LeakShield({
    customRules: [
      {
        id: 'internal-id',
        name: 'Internal ID',
        pattern: /INTERNAL_SECRET_[0-9]+/g,
      },
    ],
  });

  const text = 'Config: INTERNAL_SECRET_987654321';
  assert.equal(shield.redact(text), 'Config: [REDACTED]');
});

test('supports disabled rules', () => {
  const shield = new LeakShield({
    disabledRules: ['openai-key'],
  });

  const text = 'Key: sk-proj-1234567890abcdef1234567890';
  assert.equal(shield.redact(text), text);
});

test('redacts sensitive keys and values in deep objects', () => {
  const payload = {
    user: {
      id: 42,
      username: 'alice',
      password: 'superSecretPassword123!',
      apiKey: 'sk-proj-1234567890abcdef1234567890',
      nested: {
        authorization_token: 'Bearer xyz987654321',
      },
    },
    meta: {
      tags: ['public', 'auth: Bearer mySecretToken12345'],
    },
  };

  const sanitized = leakShield.redactObject(payload);

  assert.equal(sanitized.user.password, '[REDACTED]');
  assert.equal(sanitized.user.apiKey, '[REDACTED]');
  assert.equal(sanitized.user.nested.authorization_token, '[REDACTED]');
  assert.equal(sanitized.user.username, 'alice');
  assert.equal(sanitized.user.id, 42);
  assert.ok(sanitized.meta.tags[1].includes('[REDACTED]'));
});

test('handles circular references safely in objects', () => {
  const obj: Record<string, unknown> = { name: 'test' };
  obj.self = obj;

  const sanitized = leakShield.redactObject(obj);
  assert.equal(sanitized.self, '[Circular]');
});
