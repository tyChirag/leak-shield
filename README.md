# leak-shield

Zero-dependency, high-speed redaction tool for secrets, API tokens, and sensitive data in strings, objects, and Node.js streams.

## Features

- **Zero dependencies**: Pure TypeScript/JavaScript with minimal footprint.
- **Multi-target protection**: Redacts plain text, nested JavaScript objects/arrays, Node.js streams, and intercepts `console` methods.
- **Built-in patterns**: Covers OpenAI, Anthropic, GitHub, AWS, Stripe, Slack, Bearer headers, JWTs, private keys, and credit cards.
- **Customizable**: Add custom regex rules, adjust mask format (`simple`, `named`, `partial`), or disable specific rules.
- **Safe object handling**: Recursively sanitizes objects while safely handling circular references, Buffers, Dates, and Errors.

## Installation

```bash
npm install leak-shield
```

## Quick Start

### 1. Basic String Redaction

```typescript
import { leakShield } from 'leak-shield';

const rawLog = 'User initiated session with key sk-proj-abcdef123456789012345678';
const safeLog = leakShield.redact(rawLog);

console.log(safeLog);
// => "User initiated session with key [REDACTED]"
```

### 2. Deep Object Sanitization

```typescript
import { leakShield } from 'leak-shield';

const payload = {
  id: 101,
  username: 'alex',
  password: 'superSecretPassword!',
  apiKey: 'sk-proj-abcdef123456789012345678',
  headers: {
    authorization: 'Bearer tokenValue123'
  }
};

const sanitized = leakShield.redactObject(payload);
console.log(sanitized);
// Password, apiKey, and authorization headers are safely masked.
```

### 3. Node.js Transform Stream

Pipe stdout or file streams through `leak-shield`:

```typescript
import { createLeakShieldStream } from 'leak-shield';

// Pipe any readable stream through the shield
readableStream
  .pipe(createLeakShieldStream())
  .pipe(process.stdout);
```

### 4. Console Interceptor

Scrub sensitive tokens from all outgoing `console.log` calls:

```typescript
import { leakShield, patchConsole } from 'leak-shield';

// Automatically redacts strings and objects passed to console
const restore = patchConsole(leakShield);

console.log('API key is:', 'sk-proj-1234567890abcdef1234567890');
// Output: API key is: [REDACTED]

// Restore original console behavior when needed
restore();
```

### 5. Formatting Options

```typescript
import { LeakShield } from 'leak-shield';

// Named rule labels
const namedShield = new LeakShield({ formatMode: 'named' });
namedShield.redact('sk-proj-abcdef123456789012345678');
// => "[REDACTED: OpenAI API Key]"

// Partial masking (preserves prefix and tail)
const partialShield = new LeakShield({ formatMode: 'partial' });
partialShield.redact('sk-proj-abcdef123456789012345678');
// => "sk-p...5678"
```

## Adding Custom Rules

```typescript
import { LeakShield } from 'leak-shield';

const customShield = new LeakShield({
  customRules: [
    {
      id: 'customer-id',
      name: 'Customer ID',
      pattern: /CUST-[0-9]{8}/g,
    }
  ]
});
```

## Publishing to npm

1. Authenticate with npm:
   ```bash
   npm login
   ```
2. Build and verify tests:
   ```bash
   npm test
   npm run build
   ```
3. Publish:
   ```bash
   npm publish --access public
   ```

## License

MIT
