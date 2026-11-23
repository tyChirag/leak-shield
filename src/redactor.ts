import { LeakShieldOptions, Rule, MaskFormatter } from './types.js';
import { DEFAULT_RULES, DEFAULT_SENSITIVE_KEYS, createPartialMask } from './patterns.js';

export class LeakShield {
  private rules: Rule[];
  private sensitiveKeys: Set<string>;
  private formatMode: 'simple' | 'named' | 'partial';
  private customMask?: string | MaskFormatter;

  constructor(options: LeakShieldOptions = {}) {
    const disabled = new Set(options.disabledRules || []);
    const baseRules = DEFAULT_RULES.filter((rule) => !disabled.has(rule.id));
    const custom = options.customRules || [];

    this.rules = [...baseRules, ...custom];
    this.formatMode = options.formatMode || 'simple';
    this.customMask = options.mask;

    const keys = options.sensitiveKeys || DEFAULT_SENSITIVE_KEYS;
    this.sensitiveKeys = new Set(keys.map((k) => k.toLowerCase()));
  }

  /**
   * Resolves the masked string for a matched secret rule
   */
  private formatMatch(matched: string, rule: Rule): string {
    if (typeof this.customMask === 'function') {
      return this.customMask(matched, rule);
    }
    if (typeof this.customMask === 'string') {
      return this.customMask;
    }
    if (rule.mask) {
      return typeof rule.mask === 'function' ? rule.mask(matched) : rule.mask;
    }

    switch (this.formatMode) {
      case 'named':
        return `[REDACTED: ${rule.name}]`;
      case 'partial':
        return createPartialMask(matched);
      case 'simple':
      default:
        return '[REDACTED]';
    }
  }

  /**
   * Redacts secrets and sensitive tokens from a plain string
   */
  redact(input: string): string {
    if (!input || typeof input !== 'string') {
      return input;
    }

    let result = input;
    for (const rule of this.rules) {
      // Reset lastIndex for global regexes
      rule.pattern.lastIndex = 0;
      result = result.replace(rule.pattern, (matched) => this.formatMatch(matched, rule));
    }

    return result;
  }

  /**
   * Deeply redacts sensitive keys and values inside an object, array, or error.
   * Circular references are handled safely.
   */
  redactObject<T>(input: T, seen = new WeakSet()): T {
    if (input === null || typeof input !== 'object') {
      if (typeof input === 'string') {
        return this.redact(input) as unknown as T;
      }
      return input;
    }

    // Pass through primitives, Buffers, Dates, RegExp
    if (
      input instanceof Date ||
      input instanceof RegExp ||
      (typeof Buffer !== 'undefined' && Buffer.isBuffer(input))
    ) {
      return input;
    }

    // Handle circular structures
    if (seen.has(input)) {
      return '[Circular]' as unknown as T;
    }
    seen.add(input);

    if (Array.isArray(input)) {
      return input.map((item) => this.redactObject(item, seen)) as unknown as T;
    }

    if (input instanceof Error) {
      const copy = new (input.constructor as new (message?: string) => Error)(
        this.redact(input.message)
      );
      if (input.stack) {
        copy.stack = this.redact(input.stack);
      }
      return copy as unknown as T;
    }

    const output: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input)) {
      const normalizedKey = key.toLowerCase().replace(/[-_]/g, '');
      const isSensitiveKey = Array.from(this.sensitiveKeys).some((sensitive) =>
        normalizedKey.includes(sensitive.replace(/[-_]/g, ''))
      );

      if (isSensitiveKey) {
        if (typeof value === 'string') {
          output[key] = this.formatMode === 'partial' ? createPartialMask(value) : '[REDACTED]';
        } else if (typeof value === 'number' || typeof value === 'boolean') {
          output[key] = '[REDACTED]';
        } else {
          output[key] = this.redactObject(value, seen);
        }
      } else {
        output[key] = this.redactObject(value, seen);
      }
    }

    return output as T;
  }

  /**
   * Returns list of configured active rules
   */
  getRules(): ReadonlyArray<Rule> {
    return this.rules;
  }
}
