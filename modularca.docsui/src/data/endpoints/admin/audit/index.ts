import type { ApiEndpoint } from '../../types';
import { adminAudit } from './audit';
import { adminCompliance } from './compliance';
import { adminPolicy } from './policy';
import { adminVulnerabilities } from './vulnerabilities';
import { adminBackup } from './backup';
import { adminContinuity } from './continuity';

export const adminAuditEndpoints: ApiEndpoint[] = [
    ...adminAudit,
    ...adminCompliance,
    ...adminPolicy,
    ...adminVulnerabilities,
    ...adminBackup,
    ...adminContinuity,
];
