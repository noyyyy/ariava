export const BUN_EXECUTABLE_ENV = 'ARIAVA_BUN_EXECUTABLE';

export function resolveBunExecutable(options = {}) {
  const explicit = options.bunPath?.trim();
  if (explicit) return explicit;

  const configured = options.env?.[BUN_EXECUTABLE_ENV]?.trim();
  return configured || 'bun';
}
