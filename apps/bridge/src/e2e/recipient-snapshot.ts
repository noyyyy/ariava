import type { E2ERecipientSnapshotV1 } from '@ariava/protocol';
import type { ActiveRecipientMaterial } from './envelope';
import type { LocalLinkKeyring } from './link-keyring';

export class RecipientSnapshotCache {
  private snapshot?: E2ERecipientSnapshotV1;
  constructor(private readonly hostId: string, private readonly keyring: LocalLinkKeyring) {}
  accept(snapshot: E2ERecipientSnapshotV1): { versionChanged: boolean; recipients: ActiveRecipientMaterial[] } {
    if (snapshot.hostId !== this.hostId || (this.snapshot && snapshot.recipientSetVersion < this.snapshot.recipientSetVersion)) {
      throw new TypeError('recipient snapshot rollback rejected');
    }
    const versionChanged = this.snapshot?.recipientSetVersion !== snapshot.recipientSetVersion;
    const recipients = this.keyring.reconcileRecipients(snapshot);
    this.snapshot = structuredClone(snapshot);
    return { versionChanged, recipients };
  }
  invalidate(): void { this.snapshot = undefined; }
  current(): E2ERecipientSnapshotV1 | undefined { return this.snapshot && structuredClone(this.snapshot); }
}
