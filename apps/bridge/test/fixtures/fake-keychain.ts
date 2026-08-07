import {
  MACOS_SECURITY_PATH,
  type KeychainCommandResult,
  type KeychainCommandRunner,
} from '../../src/identity/macos-keychain-store';

export interface FakeKeychainCall {
  command: string;
  args: readonly string[];
  stdin?: Uint8Array;
  account?: string;
  action: 'read' | 'write' | 'delete' | 'unsupported';
}

export class FakeKeychain implements KeychainCommandRunner {
  readonly calls: FakeKeychainCall[] = [];
  readonly items = new Map<string, Uint8Array>();

  run(command: string, args: readonly string[], stdin?: Uint8Array): KeychainCommandResult {
    if (command !== MACOS_SECURITY_PATH) return this.record(command, args, stdin, undefined, 'unsupported');
    if (args.length === 1 && args[0] === '-i' && stdin) {
      const script = Buffer.from(stdin).toString('utf8');
      const account = /-a "([^"]+)"/u.exec(script)?.[1];
      const hex = /-X ([0-9a-f]+)/u.exec(script)?.[1];
      if (!account || !hex) return this.record(command, args, stdin, account, 'unsupported', 1, 'invalid stdin');
      if (!script.includes(' -U ') && this.items.has(account)) {
        return this.record(command, args, stdin, account, 'write', 45, 'item already exists');
      }
      this.items.set(account, Buffer.from(hex, 'hex'));
      return this.record(command, args, stdin, account, 'write');
    }

    const account = args[args.indexOf('-a') + 1];
    if (args[0] === 'add-generic-password') {
      const hex = args[args.indexOf('-X') + 1];
      if (!account || !hex) return this.record(command, args, stdin, account, 'unsupported', 1, 'invalid args');
      const update = args.includes('-U');
      if (!update && this.items.has(account)) {
        return this.record(command, args, stdin, account, 'write', 45, 'item already exists');
      }
      this.items.set(account, Buffer.from(hex, 'hex'));
      return this.record(command, args, stdin, account, 'write');
    }
    if (args[0] === 'find-generic-password') {
      const value = this.items.get(account);
      return value
        ? this.record(command, args, stdin, account, 'read', 0, '', Buffer.from(`${Buffer.from(value).toString('hex')}\n`, 'utf8'))
        : this.record(command, args, stdin, account, 'read', 44, 'could not be found');
    }
    if (args[0] === 'delete-generic-password') {
      this.items.delete(account);
      return this.record(command, args, stdin, account, 'delete');
    }
    return this.record(command, args, stdin, account, 'unsupported', 1, 'unsupported');
  }

  callsFor(account: string): FakeKeychainCall[] {
    return this.calls.filter((call) => call.account === account);
  }

  snapshot(account: string): Uint8Array | undefined {
    const value = this.items.get(account);
    return value ? new Uint8Array(value) : undefined;
  }

  resetCalls(): void {
    this.calls.length = 0;
  }

  private record(
    command: string,
    args: readonly string[],
    stdin: Uint8Array | undefined,
    account: string | undefined,
    action: FakeKeychainCall['action'],
    status = 0,
    stderr = '',
    stdout: Uint8Array = new Uint8Array(),
  ): KeychainCommandResult {
    this.calls.push({ command, args, ...(stdin ? { stdin } : {}), ...(account ? { account } : {}), action });
    return { status, stdout, stderr };
  }
}
