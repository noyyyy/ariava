import { beforeEach, describe, expect, test } from 'bun:test';
import {
  classifyStoredAssistantText,
  extractBlockedReason,
  looksLikeQuestion,
  markFingerprintEmitted,
  resetEmittedFingerprints,
} from '../src/question-detector';

describe('classifyStoredAssistantText', () => {
  beforeEach(() => resetEmittedFingerprints());

  test('classifies a stored question without consulting session history', () => {
    const result = classifyStoredAssistantText('What should I name this file?', {
      sessionId: 'session-1',
      activeLeafId: 'leaf-1',
    });

    expect(result.type).toBe('question_requested');
    expect(result.assistantText).toBe('What should I name this file?');
  });

  test('classifies stored explicit blocked evidence', () => {
    const result = classifyStoredAssistantText('I need your credentials before continuing.', {
      sessionId: 'session-1',
    });

    expect(result.type).toBe('blocked');
    expect(result.assistantText).toContain('credentials');
  });

  test('classifies stable stored text as done by default', () => {
    const result = classifyStoredAssistantText('I have updated the configuration file.', {
      sessionId: 'session-1',
    });

    expect(result.type).toBe('done');
    expect(result.assistantText).toBe('I have updated the configuration file.');
  });

  test('uses the stable done fallback for empty stored text', () => {
    const result = classifyStoredAssistantText(undefined, { sessionId: 'session-1' });
    expect(result.type).toBe('done');
    expect(result.assistantText).toBe('Task complete');
  });

  test('suppresses an emitted fingerprint in the same session and active leaf', () => {
    const first = classifyStoredAssistantText('Can you confirm the choice?', {
      sessionId: 'session-1',
      activeLeafId: 'leaf-1',
    });
    markFingerprintEmitted(first.fingerprint);

    expect(classifyStoredAssistantText('Can you confirm the choice?', {
      sessionId: 'session-1',
      activeLeafId: 'leaf-1',
    }).type).toBe('suppress_duplicate');
  });

  test('scopes duplicate fingerprints by session and active leaf', () => {
    const first = classifyStoredAssistantText('Can you confirm the choice?', {
      sessionId: 'session-1',
      activeLeafId: 'leaf-1',
    });
    markFingerprintEmitted(first.fingerprint);

    expect(classifyStoredAssistantText('Can you confirm the choice?', {
      sessionId: 'session-2',
      activeLeafId: 'leaf-1',
    }).type).toBe('question_requested');
    expect(classifyStoredAssistantText('Can you confirm the choice?', {
      sessionId: 'session-1',
      activeLeafId: 'leaf-2',
    }).type).toBe('question_requested');
  });
});

describe('stable stop-text heuristics', () => {
  test('detects blocked reasons without provider or retry taxonomy', () => {
    expect(extractBlockedReason('permission denied while editing package.json')).toBe('permission denied while editing package.json');
    expect(extractBlockedReason('requires manual review before deploy')).toBe('requires manual review before deploy');
    expect(extractBlockedReason('All changes complete')).toBeUndefined();
  });

  test('detects question phrasing', () => {
    expect(looksLikeQuestion('Which environment would you like me to use')).toBe(true);
    expect(looksLikeQuestion('I updated the file.')).toBe(false);
  });
});
