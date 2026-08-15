import type {
  E2EEventAndSessionUploadV3,
  EncryptedContentV1,
  EncryptedEventProjectionV3,
  EncryptedEventUploadV3,
  EncryptedSessionProjectionV3,
  EncryptedSessionSnapshotUploadV3,
  ProtectedEventContentV3,
  ProtectedSessionContentV3,
  RecipientKeyWrapV1,
  RelayEventMetadataV3,
} from '../../src/index.js';

const eventContent: ProtectedEventContentV3 = {
  version: 3,
  agentText: 'Which target should I use?',
  humanText: 'Deploy the service.',
  projectName: 'ariava',
  workingDirectory: '/workspace/ariava',
  harnessProvider: 'pi',
  needHuman: { reason: 'question' },
};

const sessionContent: ProtectedSessionContentV3 = {
  version: 3,
  projectName: 'ariava',
  nameText: 'Release preparation',
  openingText: 'Prepare the release.',
  latestActivityText: 'Waiting for a target.',
  workingDirectory: '/workspace/ariava',
  harnessProvider: 'pi',
};

const encryptedEventContent = {
  version: 1,
  suite: 'x25519-hkdf-sha256-chachapoly-v1',
  contentId: 'content-event-1',
  payloadKind: 'event-content-v3',
  nonce: 'AAAAAAAAAAAAAAAA',
  ciphertext: 'AAAAAAAAAAAAAAAAAAAAAA',
} satisfies EncryptedContentV1 & { payloadKind: 'event-content-v3' };

const encryptedSessionContent = {
  ...encryptedEventContent,
  contentId: 'content-session-1',
  payloadKind: 'session-content-v3',
} satisfies EncryptedContentV1 & { payloadKind: 'session-content-v3' };

const keyWrap: RecipientKeyWrapV1 = {
  version: 1,
  suite: 'x25519-hkdf-sha256-chachapoly-v1',
  contentId: 'content-event-1',
  linkId: 'link-1',
  linkGeneration: 1,
  epoch: 1,
  senderEncryptionKeyId: 'ekey-host',
  recipientEncryptionKeyId: 'ekey-watch',
  nonce: 'AAAAAAAAAAAAAAAA',
  ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
};

const eventMetadata = {
  eventId: 'event-1',
  hostId: 'host-1',
  sessionId: 'session-1',
  provider: 'pi',
  createdAt: '2026-08-14T00:00:00.000Z',
  type: 'need_human',
  status: 'need_human',
} satisfies RelayEventMetadataV3;

const eventUpload: EncryptedEventUploadV3 = {
  ...eventMetadata,
  recipientSetVersion: 1,
  content: encryptedEventContent,
  keyWraps: [keyWrap],
};

const eventProjection: EncryptedEventProjectionV3 = {
  ...eventMetadata,
  content: encryptedEventContent,
  keyWrap,
};

const sessionUpload: EncryptedSessionSnapshotUploadV3 = {
  hostId: 'host-1',
  sessionId: 'session-1',
  provider: 'pi',
  status: 'need_human',
  updatedAt: '2026-08-14T00:00:01.000Z',
  lastEventId: 'event-1',
  revision: 1,
  recipientSetVersion: 1,
  content: encryptedSessionContent,
  keyWraps: [{ ...keyWrap, contentId: 'content-session-1' }],
};

const sessionProjection: EncryptedSessionProjectionV3 = {
  hostId: sessionUpload.hostId,
  sessionId: sessionUpload.sessionId,
  provider: sessionUpload.provider,
  status: sessionUpload.status,
  updatedAt: sessionUpload.updatedAt,
  lastEventId: sessionUpload.lastEventId,
  revision: sessionUpload.revision,
  content: encryptedSessionContent,
  keyWrap: { ...keyWrap, contentId: 'content-session-1' },
};

const combinedUpload: E2EEventAndSessionUploadV3 = {
  event: eventUpload,
  session: sessionUpload,
};

// @ts-expect-error current Event plaintext requires version 3
const eventV2: ProtectedEventContentV3 = { version: 2, agentText: 'legacy' };
// @ts-expect-error retired Event protected fields are not assignable
const eventWithRetiredField: ProtectedEventContentV3 = { version: 3, agentText: 'current', contextText: 'retired' };
// @ts-expect-error current Session plaintext requires version 3
const sessionV2: ProtectedSessionContentV3 = { version: 2, projectName: 'ariava', nameText: 'legacy' };
// @ts-expect-error retired Session protected fields are not assignable
const sessionWithRetiredField: ProtectedSessionContentV3 = { version: 3, projectName: 'ariava', nameText: 'current', hbaseSessionKey: 'retired' };
// @ts-expect-error done Event metadata must pair with idle status
const invalidEventMetadata: RelayEventMetadataV3 = { ...eventMetadata, type: 'done', status: 'need_human' };
// @ts-expect-error Event v3 metadata has no correlationId
const correlatedEventMetadata: RelayEventMetadataV3 = { ...eventMetadata, correlationId: 'retired' };
// @ts-expect-error Event upload content must use event-content-v3
const eventUploadWithSessionKind: EncryptedEventUploadV3 = { ...eventUpload, content: encryptedSessionContent };
// @ts-expect-error Event projection requires one keyWrap, not upload keyWraps
const eventProjectionWithUploadWraps: EncryptedEventProjectionV3 = { ...eventMetadata, content: encryptedEventContent, keyWraps: [keyWrap] };
// @ts-expect-error Session upload content must use session-content-v3
const sessionUploadWithEventKind: EncryptedSessionSnapshotUploadV3 = { ...sessionUpload, content: encryptedEventContent };
// @ts-expect-error Session projection requires one keyWrap, not upload keyWraps
const sessionProjectionWithUploadWraps: EncryptedSessionProjectionV3 = { ...sessionProjection, keyWraps: [keyWrap] };
// @ts-expect-error combined upload Session member must be the v3 Session upload contract
const combinedWithProjection: E2EEventAndSessionUploadV3 = { event: eventUpload, session: sessionProjection };

void [
  eventContent,
  sessionContent,
  eventMetadata,
  eventUpload,
  eventProjection,
  sessionUpload,
  sessionProjection,
  combinedUpload,
  eventV2,
  eventWithRetiredField,
  sessionV2,
  sessionWithRetiredField,
  invalidEventMetadata,
  correlatedEventMetadata,
  eventUploadWithSessionKind,
  eventProjectionWithUploadWraps,
  sessionUploadWithEventKind,
  sessionProjectionWithUploadWraps,
  combinedWithProjection,
];
