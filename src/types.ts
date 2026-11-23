export interface Rule {
  id: string;
  name: string;
  pattern: RegExp;
  mask?: string | ((matched: string) => string);
  description?: string;
}

export type MaskFormatter = (matched: string, rule: Rule) => string;

export interface LeakShieldOptions {
  /**
   * Custom replacement string or custom formatter function.
   */
  mask?: string | MaskFormatter;

  /**
   * Formatting mode for redaction:
   * - 'simple': replaces with "[REDACTED]"
   * - 'named': replaces with "[REDACTED: <RULE_NAME>]"
   * - 'partial': preserves first few and last few characters (e.g. "sk-123***89")
   * Default: 'simple'
   */
  formatMode?: 'simple' | 'named' | 'partial';

  /**
   * List of rule IDs to disable.
   */
  disabledRules?: string[];

  /**
   * Additional custom rules to apply.
   */
  customRules?: Rule[];

  /**
   * Object keys to mask in deep object sanitization.
   * Default includes: ['password', 'secret', 'token', 'apikey', 'authorization', 'creditcard', 'privatekey']
   */
  sensitiveKeys?: string[];
}

export interface StreamShieldOptions extends LeakShieldOptions {
  /**
   * Default chunk string encoding. Defaults to 'utf8'.
   */
  encoding?: BufferEncoding;
}
