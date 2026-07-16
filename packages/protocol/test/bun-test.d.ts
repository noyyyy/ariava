declare module 'bun:test' {
  interface Matchers<T = unknown> {
    toBe(expected: unknown): void;
    toEqual(expected: unknown): void;
    toBeUndefined(): void;
    toBeNull(): void;
    toContain(expected: unknown): void;
    toThrow(expected?: string | RegExp): void;
    rejects: Matchers<Awaited<T>>;
  }

  export function describe(name: string, fn: () => void): void;
  export interface TestFunction {
    (name: string, fn: () => void | Promise<void>): void;
    each<T extends readonly unknown[]>(cases: readonly T[]): (name: string, fn: (...args: T) => void | Promise<void>) => void;
  }
  export const test: TestFunction;
  export function expect<T = unknown>(actual: T): Matchers<T>;
}
