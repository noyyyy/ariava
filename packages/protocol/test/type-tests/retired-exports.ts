import type * as Protocol from '../../src/index.js';

// @ts-expect-error retired prompt type is not public
export type RetiredActionablePrompt = Protocol.ActionablePrompt;
// @ts-expect-error retired protected prompt type is not public
export type RetiredProtectedActionablePrompt = Protocol.ProtectedActionablePromptV1;
// @ts-expect-error retired Event v2 metadata is not public
export type RetiredRelayEventMetadata = Protocol.RelayEventMetadataV2;
// @ts-expect-error retired Event v2 upload is not public
export type RetiredEncryptedEventUpload = Protocol.EncryptedEventUploadV2;
// @ts-expect-error retired Event v2 projection is not public
export type RetiredEncryptedEventProjection = Protocol.EncryptedEventProjectionV2;
// @ts-expect-error retired Session v2 upload is not public
export type RetiredEncryptedSessionUpload = Protocol.EncryptedSessionSnapshotUploadV2;
// @ts-expect-error retired Session v2 projection is not public
export type RetiredEncryptedSessionProjection = Protocol.EncryptedSessionProjectionV2;
// @ts-expect-error retired combined v2 upload is not public
export type RetiredCombinedUpload = Protocol.E2EEventAndSessionUploadV2;
