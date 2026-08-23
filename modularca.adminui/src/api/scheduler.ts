/// <summary>
/// Typed API client for the Schedules admin page. Wraps the
/// /api/v1/admin/scheduler endpoints plus the existing CRL/LDAP edit and
/// delete endpoints. Step-up MFA is required for any mutating call here, so
/// the helpers all accept the requireStepUp callback from
/// <see cref="StepUpMfaContext"/>.
/// </summary>
import {
    apiGet,
    apiPostWithMfa,
    apiPutWithMfa,
    apiDeleteWithMfa,
} from './client';
import { StepUpOps } from '@shared/generated';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SchedulerLeaseHolder {
    instanceId: string;
    acquiredAtUtc: string;
    expiresAtUtc: string;
}

export interface SchedulerHealth {
    leaseHolder: SchedulerLeaseHolder | null;
    pollIntervalSeconds: number;
    leaseTtlSeconds: number;
    missedRunPolicy: string;
    defaultJobTimeoutSeconds: number;
    consecutiveFailureAlertThreshold: number;
}

export type JobResult = 'success' | 'failed' | 'cancelled' | null;

export interface SchedulerJob {
    name: string;
    cronExpression: string;
    enabled: boolean;
    timeoutSeconds: number;
    lastRunUtc: string | null;
    lastResult: JobResult;
    lastDurationMs: number | null;
    lastError: string | null;
    consecutiveFailureCount: number;
    nextRunUtc: string | null;
}

export interface CrlScheduleEntry {
    taskId: string;
    caCertificateId: string;
    caLabel: string;
    name: string;
    enabled: boolean;
    updateInterval: string;
    deltaInterval: string | null;
    isDelta: boolean;
    nextUpdateUtc: string | null;
    nextDeltaRunUtc: string | null;
    lastUpdatedUtc: string | null;
    lastGenerated: string | null;
    lastCrlNumber: number | null;
}

export interface LdapPublisherEntry {
    id: string;
    certificateAuthorityId: string;
    caLabel: string;
    host: string;
    port: number;
    baseDn: string;
    enabled: boolean;
    updateInterval: string;
    nextUpdateUtc: string | null;
    lastUpdatedUtc: string | null;
    publishCACert: boolean;
    publishCRL: boolean;
    publishDelta: boolean;
    publishUserCerts: boolean;
}

export interface SchedulerSchedules {
    crl: CrlScheduleEntry[];
    ldap: LdapPublisherEntry[];
}

export interface SchedulerConfigUpdate {
    leaseTtlSeconds?: number;
    missedRunPolicy?: string;
    defaultJobTimeoutSeconds?: number;
    consecutiveFailureAlertThreshold?: number;
}

export interface SchedulerJobUpdate {
    cronExpression?: string;
    timeoutSeconds?: number;
}

type StepUpFn = (operation: string, targetId?: string) => Promise<string>;

const BASE = '/api/v1/admin/scheduler';

// ---------------------------------------------------------------------------
// Health + lookups
// ---------------------------------------------------------------------------

/// <summary>Reads the scheduler lease holder + read-only config.</summary>
export function getSchedulerHealth(): Promise<SchedulerHealth> {
    return apiGet<SchedulerHealth>(`${BASE}/health`);
}

/// <summary>Lists all registered system jobs with their last/next run state.</summary>
export function getSchedulerJobs(): Promise<SchedulerJob[]> {
    return apiGet<SchedulerJob[]>(`${BASE}/jobs`);
}

/// <summary>Lists CRL and LDAP per-CA schedules in a single call.</summary>
export function getSchedulerSchedules(): Promise<SchedulerSchedules> {
    return apiGet<SchedulerSchedules>(`${BASE}/schedules`);
}

// ---------------------------------------------------------------------------
// Mutations (step-up MFA)
// ---------------------------------------------------------------------------

/// <summary>Updates a system job's cron and/or timeout. Requires step-up MFA.</summary>
export function updateSchedulerJob(
    name: string,
    body: SchedulerJobUpdate,
    stepUp: StepUpFn,
): Promise<void> {
    return apiPutWithMfa<void>(
        `${BASE}/jobs/${encodeURIComponent(name)}`,
        body,
        stepUp,
        StepUpOps.UpdateSchedulerJob,
        name,
    );
}

/// <summary>Triggers a system job to run immediately. Requires step-up MFA.</summary>
export function runSchedulerJob(name: string, stepUp: StepUpFn): Promise<void> {
    return apiPostWithMfa<void>(
        `${BASE}/jobs/${encodeURIComponent(name)}/run`,
        undefined,
        stepUp,
        StepUpOps.RunSchedulerJob,
        name,
    );
}

/// <summary>Triggers an out-of-band CRL generation for a single CRL schedule.</summary>
export function runCrlSchedule(taskId: string, stepUp: StepUpFn): Promise<void> {
    return apiPostWithMfa<void>(
        `${BASE}/schedules/crl/${encodeURIComponent(taskId)}/run`,
        undefined,
        stepUp,
        StepUpOps.RunSchedulerSchedule,
        taskId,
    );
}

/// <summary>Triggers an out-of-band LDAP publish for a single publisher.</summary>
export function runLdapSchedule(id: string, stepUp: StepUpFn): Promise<void> {
    return apiPostWithMfa<void>(
        `${BASE}/schedules/ldap/${encodeURIComponent(id)}/run`,
        undefined,
        stepUp,
        StepUpOps.RunSchedulerSchedule,
        id,
    );
}

/// <summary>Updates the global scheduler tunables. Requires step-up MFA.</summary>
export function updateSchedulerConfig(
    body: SchedulerConfigUpdate,
    stepUp: StepUpFn,
): Promise<void> {
    return apiPutWithMfa<void>(
        `${BASE}/config`,
        body,
        stepUp,
        StepUpOps.UpdateSchedulerConfig,
    );
}

// ---------------------------------------------------------------------------
// CRL / LDAP CRUD reuse the existing admin controllers
// ---------------------------------------------------------------------------

/// <summary>Edits an existing CRL schedule via the existing admin endpoint.</summary>
export function updateCrlSchedule(
    taskId: string,
    body: { updateInterval?: string; deltaInterval?: string | null; isDelta?: boolean; description?: string; overlapPeriod?: string },
    stepUp: StepUpFn,
): Promise<void> {
    return apiPutWithMfa<void>(
        `/api/v1/admin/crl-schedules/${encodeURIComponent(taskId)}`,
        body,
        stepUp,
        StepUpOps.UpdateCrlSchedule,
        taskId,
    );
}

/// <summary>Deletes a CRL schedule via the existing admin endpoint.</summary>
export function deleteCrlSchedule(taskId: string, stepUp: StepUpFn): Promise<void> {
    return apiDeleteWithMfa(
        `/api/v1/admin/crl-schedules/${encodeURIComponent(taskId)}`,
        stepUp,
        StepUpOps.DeleteCrlSchedule,
        taskId,
    );
}

/// <summary>Edits an existing LDAP publisher via the existing admin endpoint.</summary>
export function updateLdapPublisher(
    id: string,
    body: { host?: string; port?: number; baseDn?: string; updateInterval?: string; enabled?: boolean; publishCACert?: boolean; publishCRL?: boolean; publishDelta?: boolean; publishUserCerts?: boolean },
    stepUp: StepUpFn,
): Promise<void> {
    return apiPutWithMfa<void>(
        `/api/v1/admin/ldap-publishers/${encodeURIComponent(id)}`,
        body,
        stepUp,
        StepUpOps.UpdateLdapPublisher,
        id,
    );
}

/// <summary>Deletes an LDAP publisher via the existing admin endpoint.</summary>
export function deleteLdapPublisher(id: string, stepUp: StepUpFn): Promise<void> {
    return apiDeleteWithMfa(
        `/api/v1/admin/ldap-publishers/${encodeURIComponent(id)}`,
        stepUp,
        StepUpOps.DeleteLdapPublisher,
        id,
    );
}

/// <summary>Toggles the enabled state of a registered system job. Calls the new
/// scheduler endpoint that flips the corresponding SystemConfig boolean
/// (e.g. Backup.CreateOnSchedule) — a feature-flag toggle would not have worked
/// because there are no FeatureFlag rows backing these per-job booleans.</summary>
export function setSchedulerJobEnabled(name: string, enabled: boolean, stepUp: StepUpFn): Promise<void> {
    return apiPutWithMfa<void>(
        `/api/v1/admin/scheduler/jobs/${encodeURIComponent(name)}/enabled`,
        { enabled },
        stepUp,
        StepUpOps.UpdateSchedulerJob,
        name,
    );
}
