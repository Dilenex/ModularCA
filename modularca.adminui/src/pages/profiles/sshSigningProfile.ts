import { validateIpOrCidr } from '@shared/validators';
import { invalidItems } from '@shared/components/chipList';
import {
    type ProfileFormMode, NAME_REQUIRED_REASON, parseJsonArray, textOrNull,
} from './profileFormCore';

/**
 * Form model for an SSH signing profile, shared by /profiles/ssh-signing/new and
 * /profiles/ssh-signing/:id.
 *
 * The DTOs are not generated (they live in AdminSshProfileController.cs, outside
 * ModularCA.Shared/Models), so their shapes are declared here. The update DTO is a patch: a null
 * member leaves the stored value alone. The update body therefore sends text fields as strings,
 * so clearing Description or Force Command clears it; sending null for an empty field, as the
 * edit page used to, made a force command impossible to remove.
 */

/** Mirrors CreateSshSigningProfileRequest in AdminSshProfileController.cs. */
export interface CreateSshSigningProfileBody {
    name: string;
    description: string | null;
    sshCaKeyId: string;
    maxValidityHours: number | null;
    allowUserCerts: boolean | null;
    allowHostCerts: boolean | null;
    forceCommand: string | null;
    sourceAddressRestrictions: string | null;
    defaultExtensions: string | null;
}

/** Mirrors UpdateSshSigningProfileRequest in AdminSshProfileController.cs (every member optional). */
export interface UpdateSshSigningProfileBody {
    name: string | null;
    description: string | null;
    sshCaKeyId: string | null;
    maxValidityHours: number | null;
    allowUserCerts: boolean | null;
    allowHostCerts: boolean | null;
    forceCommand: string | null;
    sourceAddressRestrictions: string | null;
    defaultExtensions: string | null;
}

export interface SshSigningProfileFormState {
    name: string;
    description: string;
    sshCaKeyId: string;
    /** Whole hours; blank or 0 falls back to 720 as the server's own default does. */
    maxValidityHours: string;
    allowUserCerts: boolean;
    allowHostCerts: boolean;
    forceCommand: string;
    /** A JSON array on the wire. */
    sourceAddressRestrictions: string[];
    defaultExtensions: string[];
}

export const DEFAULT_MAX_VALIDITY_HOURS = 720;

/** Whole hours from the form, falling back to the server default for blank or 0. */
export const hoursOrDefault = (value: string): number => parseInt(value, 10) || DEFAULT_MAX_VALIDITY_HOURS;

/** The form for a new SSH signing profile; the defaults are the server's create defaults. */
export const emptyForm = (): SshSigningProfileFormState => ({
    name: '', description: '', sshCaKeyId: '',
    maxValidityHours: String(DEFAULT_MAX_VALIDITY_HOURS), allowUserCerts: true, allowHostCerts: false,
    forceCommand: '', sourceAddressRestrictions: [],
    defaultExtensions: ['permit-pty'],
});

/** Seeds the form from a stored profile. */
export const formFromProfile = (p: any): SshSigningProfileFormState => ({
    name: p?.name || '',
    description: p?.description || '',
    sshCaKeyId: p?.sshCaKeyId || '',
    maxValidityHours: String(p?.maxValidityHours ?? DEFAULT_MAX_VALIDITY_HOURS),
    allowUserCerts: !!p?.allowUserCerts,
    allowHostCerts: !!p?.allowHostCerts,
    forceCommand: p?.forceCommand || '',
    sourceAddressRestrictions: parseJsonArray(p?.sourceAddressRestrictions),
    defaultExtensions: parseJsonArray(p?.defaultExtensions),
});

export const formToCreateBody = (f: SshSigningProfileFormState): CreateSshSigningProfileBody => ({
    name: f.name,
    description: textOrNull(f.description),
    sshCaKeyId: f.sshCaKeyId,
    maxValidityHours: hoursOrDefault(f.maxValidityHours),
    allowUserCerts: f.allowUserCerts,
    allowHostCerts: f.allowHostCerts,
    forceCommand: textOrNull(f.forceCommand),
    sourceAddressRestrictions: JSON.stringify(f.sourceAddressRestrictions),
    defaultExtensions: JSON.stringify(f.defaultExtensions),
});

export const formToUpdateBody = (f: SshSigningProfileFormState): UpdateSshSigningProfileBody => ({
    name: f.name,
    description: f.description,
    sshCaKeyId: textOrNull(f.sshCaKeyId),
    maxValidityHours: hoursOrDefault(f.maxValidityHours),
    allowUserCerts: f.allowUserCerts,
    allowHostCerts: f.allowHostCerts,
    forceCommand: f.forceCommand,
    sourceAddressRestrictions: JSON.stringify(f.sourceAddressRestrictions),
    defaultExtensions: JSON.stringify(f.defaultExtensions),
});

export const CA_KEY_REASON = 'Choose the SSH CA key that signs certificates under this profile.';
export const SOURCE_ADDRESS_REASON = 'Fix the source addresses marked invalid; each must be an IPv4 or IPv6 address or a CIDR network.';

/**
 * One `source-address` entry: an address or a CIDR network. OpenSSH refuses a range with bits set
 * past the prefix (10.0.0.1/8), so the network address is required.
 */
export const validateSourceAddress = (value: string): string | null =>
    validateIpOrCidr(value, { requireNetworkAddress: true });

export const SIGNS_NOTHING_REASON = 'Allow user or host certificates, or both; a profile that allows neither can sign nothing.';

/** Why Save is blocked; empty when the form may be saved. */
export const validate = (f: SshSigningProfileFormState, _mode: ProfileFormMode): string[] => {
    const reasons: string[] = [];
    if (!f.name) reasons.push(NAME_REQUIRED_REASON);
    if (!f.sshCaKeyId) reasons.push(CA_KEY_REASON);
    // The server saves such a profile, and the signing form then filters it out of every dropdown.
    if (!f.allowUserCerts && !f.allowHostCerts) reasons.push(SIGNS_NOTHING_REASON);
    if (invalidItems(f.sourceAddressRestrictions, validateSourceAddress).length > 0) reasons.push(SOURCE_ADDRESS_REASON);
    return reasons;
};
