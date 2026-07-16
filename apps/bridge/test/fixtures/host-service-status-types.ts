import type { ServiceStatus } from '../../src/host-manager/service/index';
import type { HostServiceStatusInput } from '../../src/host-manager/status';

declare const neutralStatus: ServiceStatus;

// This assignment is compiled by service-status-types.test.ts with TypeScript semantic checking.
export const portableStatus: HostServiceStatusInput = neutralStatus;
