import { Rule } from './types.js';

/**
 * Creates a partial mask preserving the head and tail of the token
 * e.g. "sk-abcdef123456" -> "sk-a...3456"
 */
export function createPartialMask(input: string): string {
  if (input.length <= 8) {
    return '***';
  }
  const headLength = Math.min(4, Math.floor(input.length / 4));
  const tailLength = Math.min(3, Math.floor(input.length / 4));
  const head = input.slice(0, headLength);
  const tail = input.slice(input.length - tailLength);
  return `${head}...${tail}`;
}

export const DEFAULT_RULES: Rule[] = [
  {
    id: 'openai-key',
    name: 'OpenAI API Key',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    description: 'Matches standard and project-scoped OpenAI API keys',
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API Key',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    description: 'Matches Anthropic Claude API keys',
  },
  {
    id: 'github-token',
    name: 'GitHub Token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
    description: 'Matches GitHub personal access and fine-grained tokens',
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    pattern: /\b(?:AKIA|ASIA|AROA)[A-Z0-9]{16}\b/g,
    description: 'Matches AWS access key IDs',
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key',
    pattern: /(?<=\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?)[A-Za-z0-9/+=]{40}(?=["']?)/gi,
    description: 'Matches AWS secret access key assignments',
  },
  {
    id: 'stripe-key',
    name: 'Stripe API Key',
    pattern: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,
    description: 'Matches Stripe standard and restricted API keys',
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    pattern: /\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/g,
    description: 'Matches Slack bot, app, and user tokens',
  },
  {
    id: 'bearer-token',
    name: 'Bearer Token',
    pattern: /(?<=\bBearer\s+)[A-Za-z0-9\-._~+/]+=*/g,
    description: 'Matches HTTP Bearer authorization tokens',
  },
  {
    id: 'jwt-token',
    name: 'JSON Web Token',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    description: 'Matches standard 3-segment JSON Web Tokens',
  },
  {
    id: 'private-key',
    name: 'Private Key Block',
    pattern: /-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+)?PRIVATE KEY-----/g,
    description: 'Matches PEM formatted private key certificates',
  },
  {
    id: 'credit-card',
    name: 'Credit Card Number',
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
    description: 'Matches major credit card number patterns',
  },
];

export const DEFAULT_SENSITIVE_KEYS: string[] = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'apikey',
  'api_key',
  'access_token',
  'auth_token',
  'authorization',
  'private_key',
  'privatekey',
  'credit_card',
  'creditcard',
  'card_number',
  'cvv',
  'cvc',
  'ssn',
];
