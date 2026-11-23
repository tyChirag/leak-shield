import { LeakShield } from './redactor.js';

export type ConsoleMethod = 'log' | 'info' | 'warn' | 'error' | 'debug';

const DEFAULT_METHODS: ConsoleMethod[] = ['log', 'info', 'warn', 'error', 'debug'];

/**
 * Monkey-patches console methods to automatically redact secrets from arguments.
 * Returns an unpatch function to restore original console behavior.
 */
export function patchConsole(
  shield: LeakShield,
  methods: ConsoleMethod[] = DEFAULT_METHODS
): () => void {
  const originalMethods = new Map<ConsoleMethod, (...args: unknown[]) => void>();

  for (const method of methods) {
    if (typeof console[method] === 'function') {
      const original = console[method].bind(console);
      originalMethods.set(method, original);

      console[method] = (...args: unknown[]) => {
        const sanitizedArgs = args.map((arg) => {
          if (typeof arg === 'string') {
            return shield.redact(arg);
          }
          if (arg !== null && typeof arg === 'object') {
            return shield.redactObject(arg);
          }
          return arg;
        });

        original(...sanitizedArgs);
      };
    }
  }

  return function unpatch(): void {
    for (const [method, original] of originalMethods.entries()) {
      console[method] = original;
    }
    originalMethods.clear();
  };
}
