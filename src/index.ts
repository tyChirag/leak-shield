import { LeakShield } from './redactor.js';
import { createLeakShieldStream } from './stream.js';
import { patchConsole } from './console.js';

// Default global singleton instance
export const leakShield = new LeakShield();

export * from './types.js';
export * from './patterns.js';
export * from './redactor.js';
export * from './stream.js';
export * from './console.js';

export default leakShield;
