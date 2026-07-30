import { describe, expect, test } from 'bun:test';
import { SessionRevisionTracker } from '../src/e2e/session-revisions';

describe('session revisions', () => {
  test('advance by exactly one and survive snapshot reload', () => {
    const tracker = new SessionRevisionTracker({});
    expect(tracker.next('session')).toBe(1);
    tracker.commit('session', 1);
    expect(() => tracker.commit('session', 1)).not.toThrow();
    expect(() => tracker.commit('session', 3)).toThrow('exactly one');
    expect(new SessionRevisionTracker(tracker.snapshot()).next('session')).toBe(2);
  });
});
