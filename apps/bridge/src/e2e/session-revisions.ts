export class SessionRevisionTracker {
  constructor(private readonly revisions: Record<string, number>) {
    for (const value of Object.values(revisions)) if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('session revision state is invalid');
  }
  current(sessionId: string): number { return this.revisions[sessionId] ?? 0; }
  next(sessionId: string): number { return this.current(sessionId) + 1; }
  commit(sessionId: string, revision: number): void {
    const current = this.current(sessionId);
    if (!Number.isSafeInteger(revision) || (revision !== current && revision !== current + 1)) throw new TypeError('session revision must advance by exactly one');
    this.revisions[sessionId] = revision;
  }
  snapshot(): Record<string, number> { return { ...this.revisions }; }
}
