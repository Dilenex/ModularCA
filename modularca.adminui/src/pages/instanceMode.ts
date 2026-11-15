/*
 * The instance mode as the console words it: the three modes with a plain account of what each
 * stops, the standing banner, and who set the mode. No React here, so it is covered by
 * tests/modularca.web.tests.
 *
 * The mode is the instance's answer to "what may I do right now". The hub sets it over its local
 * connection and an administrator sets it under Settings; the last writer wins. An instance with
 * no hub, and nothing set by hand, is always in full mode.
 */
import type { InstanceModeStatus } from '@shared/generated';

export type InstanceModeName = 'full' | 'restricted' | 'maintenance' | 'dr';

/** The event the settings card fires after a change, so the banner reloads without a page load. */
export const INSTANCE_MODE_CHANGED_EVENT = 'modca:instance-mode-changed';

export interface InstanceModeOption {
    value: InstanceModeName;
    label: string;
    /** One line: what the mode is for. */
    summary: string;
    /** What it stops. */
    stops: string;
    /** What keeps working. */
    keeps: string;
}

export const INSTANCE_MODE_OPTIONS: InstanceModeOption[] = [
    {
        value: 'full',
        label: 'Full',
        summary: 'Normal operation.',
        stops: 'Nothing.',
        keeps: 'Everything.',
    },
    {
        value: 'restricted',
        label: 'Restricted',
        summary: 'Keep issuing and revoking, and freeze everything that changes how the instance is run.',
        stops: 'Users, groups, roles, grants, profiles, policy, settings, new CAs, key operations, ceremonies, '
            + 'releasing a hold and un-revoking.',
        keeps: 'Issuing, renewing, revoking, placing a hold, disabling a CA, locking an account, CRLs, OCSP and scheduled renewal.',
    },
    {
        value: 'maintenance',
        label: 'Maintenance',
        summary: 'For an instance that is being updated or audited: issue nothing and change nothing about how it is run, '
            + 'and keep revoking and answering revocation checks.',
        stops: 'Everything restricted mode stops, and also issuing, renewing, reissuing, approving requests and enrollment '
            + 'over every protocol (ACME, EST, CMP, SCEP, Windows autoenrollment), SSH certificates and scheduled renewal.',
        keeps: 'Revoking, placing a hold, revoking a certificate this CA does not hold, disabling a CA, locking an account, '
            + 'signing CRLs, answering OCSP, timestamps, backups and the other scheduled jobs.',
    },
    {
        value: 'dr',
        label: 'DR mode',
        summary: 'Stop everything except signing in to manage and repair the instance.',
        stops: 'Everything restricted mode stops, and also issuing, revoking, signing new CRLs, answering OCSP '
            + '(it reports itself unavailable), enrollment over every protocol and scheduled jobs other than backups. '
            + 'What the protocols only read (CA certificates, the ACME directory) still answers.',
        keeps: 'Signing in, backups, changing the mode, and serving CRLs that are already signed.',
    },
];

/** A mode the server sent, narrowed; anything unknown is treated as DR mode, the most restrictive. */
export function modeName(mode: string | null | undefined): InstanceModeName {
    return mode === 'full' || mode === 'restricted' || mode === 'maintenance' ? mode : mode == null ? 'full' : 'dr';
}

export function modeOption(mode: string | null | undefined): InstanceModeOption {
    const name = modeName(mode);
    return INSTANCE_MODE_OPTIONS.find((o) => o.value === name)!;
}

/** "Full mode", "Restricted mode", "Maintenance mode", "DR mode". */
export function modeTitle(mode: string | null | undefined): string {
    const name = modeName(mode);
    return name === 'full' ? 'Full mode' : name === 'restricted' ? 'Restricted mode' : name === 'maintenance' ? 'Maintenance mode' : 'DR mode';
}

/** Who set the mode, as a phrase that follows "Set by": "the hub (alice)", "administrator bob". */
export function setByText(status: Pick<InstanceModeStatus, 'source' | 'setBy'>): string {
    switch (status.source) {
        case 'hub':
            return status.setBy ? `the hub (operator ${status.setBy}, as the hub named them)` : 'the hub';
        case 'administrator':
            return status.setBy ? `administrator ${status.setBy}` : 'an administrator';
        case 'start':
            return 'the start rule: this instance has a hub connection and no mode had been set yet';
        case 'unreadable':
            return 'nobody: the mode record on this host could not be read, so the instance holds itself restricted';
        default:
            return 'nobody: this is the default';
    }
}

export interface InstanceModeBanner {
    tone: 'warn' | 'crit';
    title: string;
    text: string;
}

/**
 * In a mode that signs no new CRL: when the CRLs in force start to expire, in words. Null when the
 * server gives no such time (every mode but DR, or no CRL signed yet).
 */
export function crlDeadlineText(status: { crlsExpireFromUtc?: string | null } | null | undefined, now: Date = new Date()): string | null {
    const at = status?.crlsExpireFromUtc ? new Date(status.crlsExpireFromUtc) : null;
    if (!at || Number.isNaN(at.getTime())) return null;
    const when = at.toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    return at.getTime() <= now.getTime()
        ? `No new CRL is signed in this mode, and a CRL in force expired on ${when}: relying parties that check it now see an expired CRL.`
        : `No new CRL is signed in this mode. The CRLs in force start to expire on ${when}; after that, relying parties see an expired CRL until the mode is lifted.`;
}

/** The standing banner, or null in full mode (and while the mode is not known). */
export function instanceModeBanner(status: InstanceModeStatus | null | undefined): InstanceModeBanner | null {
    if (!status) return null;
    const name = modeName(status.mode);
    if (name === 'full') return null;
    const option = modeOption(name);
    const by = status.source === 'hub' ? 'Set by the hub.'
        : status.source === 'administrator' ? `Set by ${status.setBy ?? 'an administrator'}.`
        : status.source === 'unreadable' ? 'The mode record on this host could not be read.'
        : 'Set at start; the hub has not set a mode yet.';
    return {
        tone: name === 'dr' ? 'crit' : 'warn',
        title: `${modeTitle(name)}.`,
        text: `${name === 'dr' ? 'Nothing is issued or revoked and OCSP is unavailable.'
            : name === 'maintenance' ? 'Nothing is issued. Revoking, CRLs and OCSP go on.' : 'Issuing and revoking go on.'} `
            + `Stopped: ${lowerFirst(option.stops)} ${by}`
            + (crlDeadlineText(status) ? ` ${crlDeadlineText(status)}` : ''),
    };
}

function lowerFirst(text: string): string {
    return text.length === 0 ? text : text[0].toLowerCase() + text.slice(1);
}

/** Why the save button is blocked, or null when the change can be sent. */
export function modeChangeBlocked(current: string | null | undefined, chosen: InstanceModeName, reason: string): string | null {
    if (modeName(current) === chosen) return 'The instance is already in this mode.';
    if (reason.trim().length === 0) return 'Give a reason; it is recorded with the change.';
    if (reason.trim().length > 500) return 'The reason is limited to 500 characters.';
    return null;
}
