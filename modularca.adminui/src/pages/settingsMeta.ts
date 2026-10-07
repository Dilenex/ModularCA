/** One setting as `GET /api/v1/admin/settings` describes it. It never carries a value. */
export interface SettingDescription {
    key: string;
    /** Dotted path, as the settings endpoints name fields: `Acme.Http01.MaxAddresses`. */
    path: string;
    section: string;
    /** `database`, `host` (this host's config.yaml), `signer` or `bootstrap`. */
    kept: 'database' | 'host' | 'signer' | 'bootstrap';
    /** `live`: a saved change takes effect at once on this node. `restart`: at its next start. */
    applies: 'live' | 'restart';
    /** Where the value in force comes from. */
    source: 'database' | 'default' | 'environment' | 'file';
    secret: boolean;
    version: number | null;
    updatedBy: string | null;
    updatedAt: string | null;
}

export type SettingsIndex = Map<string, SettingDescription>;

/** The descriptions by path, in lower case: the page names a field `certManager.enabled`, the server `CertManager.Enabled`. */
export function indexSettings(settings: SettingDescription[] | null | undefined): SettingsIndex {
    const index: SettingsIndex = new Map();
    for (const s of settings || []) index.set(s.path.toLowerCase(), s);
    return index;
}

export function describeField(index: SettingsIndex, path: string | undefined): SettingDescription | undefined {
    return path ? index.get(path.toLowerCase()) : undefined;
}

export interface FieldBadge {
    label: string;
    /** `ok` and `warn` are for when a change takes effect; `neutral` for where a setting is kept. */
    tone: 'ok' | 'warn' | 'neutral';
    title: string;
}

/**
 * What to say beside a field: when a change to it takes effect, and anything about where it is
 * kept that the person saving needs to know. A field the server does not describe gets nothing.
 */
export function fieldBadges(setting: SettingDescription | undefined): FieldBadge[] {
    if (!setting) return [];
    if (setting.source === 'environment')
        return [{ label: 'Environment', tone: 'neutral', title: 'Set by an environment variable on this node, which wins. It cannot be changed here.' }];

    const badges: FieldBadge[] = [];
    if (setting.kept === 'host')
        badges.push({ label: 'This host', tone: 'neutral', title: "Kept in this host's config.yaml, not in the database. Other hosts have their own." });
    else if (setting.kept !== 'database')
        badges.push({ label: 'File', tone: 'neutral', title: 'Read from a file at start, not from the database.' });

    badges.push(setting.applies === 'live'
        ? { label: 'Live', tone: 'ok', title: 'A saved change takes effect at once on this node. Other nodes take it at their next start.' }
        : { label: 'Restart', tone: 'warn', title: 'A saved change takes effect when this node next starts.' });
    return badges;
}

/** Whether a field cannot be changed from the console: an environment variable decides it. */
export function fieldLocked(setting: SettingDescription | undefined): boolean {
    return setting?.source === 'environment';
}

/**
 * The settings each card of the Settings page edits, by the card's key. The card's header says
 * when a change takes effect from these, so the list has to be the fields the card shows:
 * tests/modularca.web.tests checks it against the page's source.
 */
export const CARD_FIELDS: Record<string, readonly string[]> = {
    baseurl: ['https.publicDomain', 'https.publicPort'],
    http: ['http.port', 'http.publicPort', 'http.corsOrigins', 'http.enableCors', 'http.swaggerEnabled'],
    metrics: ['metrics.enabled', 'metrics.path'],
    sshCa: ['sshCa.sshKeygenPath', 'sshCa.keyStoragePath'],
    backup: ['backup.outputPath', 'backup.retentionCount', 'backup.maxBackupAgeDays', 'backup.verifyOnSchedule', 'backup.verifyCount'],
    loginProtection: ['security.maxPerUsernameLoginFailures', 'security.perUsernameLoginFailureWindowMinutes'],
    tokenBinding: [
        'tokens.refreshTokenDays', 'security.bindJwtToIp', 'security.bindRefreshTokenToIp', 'security.bindRefreshTokenToFingerprint',
        'security.allowRefreshTokenMismatch',
    ],
    reverseProxy: ['security.behindReverseProxy', 'http.trustedProxyCidrs'],
    mtls: ['mtls.enabled', 'mtls.authSubdomain', 'mtls.requiredPaths', 'mtls.trustedCaCertPaths'],
    ipwhitelist: ['ipWhitelist.enabled', 'ipWhitelist.exemptPaths'],
    ldapAuth: [
        'ldapAuth.enabled', 'ldapAuth.host', 'ldapAuth.port', 'ldapAuth.useSsl', 'ldapAuth.searchBaseDn', 'ldapAuth.searchFilter', 'ldapAuth.bindDn',
        'ldapAuth.bindPassword', 'ldapAuth.groupSyncEnabled', 'ldapAuth.autoProvisionUsers', 'ldapAuth.groupSearchBaseDn',
        'ldapAuth.groupSearchFilter', 'ldapAuth.groupMemberAttribute',
    ],
    certPolicy: ['certPolicy.enabled', 'certPolicy.minRsaKeySize', 'certPolicy.requireSans', 'certPolicy.forbiddenAlgorithms'],
    autoRenewal: ['autoRenewal.enabled', 'autoRenewal.renewDaysBeforeExpiry', 'autoRenewal.autoApprove'],
    certExpiryNotification: ['certExpiryNotification.enabled', 'certExpiryNotification.warningDaysBeforeExpiry'],
    complianceScan: [
        'complianceScan.enabled', 'complianceScan.minRsaKeySize', 'complianceScan.warnOverValidityDays', 'complianceScan.deprecatedAlgorithms',
    ],
    email: [
        'email.enabled', 'email.smtpHost', 'email.smtpPort', 'email.useTls', 'email.authMethod', 'email.username', 'email.password',
        'email.oAuth2AccessToken', 'email.oAuth2ClientId', 'email.oAuth2ClientSecret', 'email.oAuth2TokenUrl', 'email.oAuth2Scopes',
        'email.fromAddress', 'email.fromName', 'email.adminRecipients',
    ],
    webhook: ['webhook.enabled', 'webhook.maxRetries', 'webhook.retryDelaySeconds'],
    certManager: ['certManager.enabled', 'certManager.apiKey', 'certManager.defaultCertProfileId', 'certManager.defaultSigningProfileId'],
    integrationApi: ['integrationApi.enabled', 'integrationApi.apiKey'],
    acme: ['acme.externalAccountRequired', 'acme.enforceCaa', 'acme.termsOfServiceUrl'],
    policySync: ['policySync.enabled', 'policySync.policyDirectory', 'policySync.syncOnStartup'],
    alert: ['alert.enabled', 'alert.minimumSeverity', 'alert.cooldownMinutes'],
    logging: ['logging.minLevel'],
    logStorage: ['logging.filePath', 'logging.retentionDays', 'logging.maxFileSizeMb', 'logging.consoleFormat'],
    networkAudit: ['networkAudit.enabled', 'networkAudit.logAllRequests', 'networkAudit.excludePaths'],
};

/**
 * When a change to these settings takes effect, for the header over them: `live` when every one
 * is, `restart` when every one waits for a restart, `mixed` otherwise, and null when the server
 * describes none of them.
 */
export function fieldsApply(index: SettingsIndex, fields: readonly string[] | undefined): 'live' | 'restart' | 'mixed' | null {
    let live = 0;
    let restart = 0;
    for (const path of fields || []) {
        const s = describeField(index, path);
        if (!s) continue;
        if (s.applies === 'live') live++; else restart++;
    }
    if (live + restart === 0) return null;
    return restart === 0 ? 'live' : live === 0 ? 'restart' : 'mixed';
}

/**
 * What can be said of a secret the console never sees: `environment` when an environment
 * variable supplies it on this node, `waiting` when a new one was stored since this node started
 * and is taken up at its next start, `stored` when it is in the database, `file` when it is
 * still in this host's config.yaml. Null when the server does not describe it.
 */
export function secretState(setting: SettingDescription | undefined, waitingForRestart: readonly string[] | null | undefined): 'environment' | 'waiting' | 'stored' | 'file' | null {
    if (!setting) return null;
    if (setting.source === 'environment') return 'environment';
    if ((waitingForRestart || []).includes(setting.key)) return 'waiting';
    return setting.version != null ? 'stored' : 'file';
}
