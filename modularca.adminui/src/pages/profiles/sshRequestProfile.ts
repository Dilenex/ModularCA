import { type ProfileFormMode, NAME_REQUIRED_REASON, parseJsonArray, textOrNull } from './profileFormCore';
import { hoursOrDefault } from './sshSigningProfile';

/**
 * Form model for an SSH request profile, shared by /profiles/ssh-request/new and
 * /profiles/ssh-request/:id. The DTOs live in AdminSshProfileController.cs and are not generated.
 *
 * The update DTO is a patch: a null CertificateAuthorityId means "leave it", so a bound profile
 * cannot be made "Any CA" by an update. The edit page used to offer that choice and the server
 * silently kept the old CA; the form now keeps the bound CA's id and refuses the unbind instead.
 */

/** Mirrors CreateSshRequestProfileRequest in AdminSshProfileController.cs. */
export interface CreateSshRequestProfileBody {
    name: string;
    description: string | null;
    allowedSshSigningProfileIds: string | null;
    allowedSshCertProfileIds: string | null;
    requireApproval: boolean | null;
    maxValidityHours: number | null;
    certificateAuthorityId: string | null;
}

/** Mirrors UpdateSshRequestProfileRequest in AdminSshProfileController.cs (every member optional). */
export interface UpdateSshRequestProfileBody {
    name: string | null;
    description: string | null;
    allowedSshSigningProfileIds: string | null;
    allowedSshCertProfileIds: string | null;
    requireApproval: boolean | null;
    maxValidityHours: number | null;
    certificateAuthorityId: string | null;
}

export interface SshRequestProfileFormState {
    name: string;
    description: string;
    allowedSshSigningProfileIds: string[];
    allowedSshCertProfileIds: string[];
    requireApproval: boolean;
    maxValidityHours: string;
    certificateAuthorityId: string;
    /** The CA the stored profile is bound to ('' when unbound or new); never sent. */
    boundCertificateAuthorityId: string;
}

/** The form for a new SSH request profile; the defaults are the server's create defaults. */
export const emptyForm = (): SshRequestProfileFormState => ({
    name: '', description: '',
    allowedSshSigningProfileIds: [], allowedSshCertProfileIds: [],
    requireApproval: false, maxValidityHours: '720',
    certificateAuthorityId: '', boundCertificateAuthorityId: '',
});

/** Seeds the form from a stored profile. */
export const formFromProfile = (p: any): SshRequestProfileFormState => ({
    name: p?.name || '',
    description: p?.description || '',
    allowedSshSigningProfileIds: parseJsonArray(p?.allowedSshSigningProfileIds),
    allowedSshCertProfileIds: parseJsonArray(p?.allowedSshCertProfileIds),
    requireApproval: !!p?.requireApproval,
    maxValidityHours: String(p?.maxValidityHours ?? 720),
    certificateAuthorityId: p?.certificateAuthorityId || '',
    boundCertificateAuthorityId: p?.certificateAuthorityId || '',
});

export const formToCreateBody = (f: SshRequestProfileFormState): CreateSshRequestProfileBody => ({
    name: f.name,
    description: textOrNull(f.description),
    allowedSshSigningProfileIds: JSON.stringify(f.allowedSshSigningProfileIds),
    allowedSshCertProfileIds: JSON.stringify(f.allowedSshCertProfileIds),
    requireApproval: f.requireApproval,
    maxValidityHours: hoursOrDefault(f.maxValidityHours),
    certificateAuthorityId: textOrNull(f.certificateAuthorityId),
});

export const formToUpdateBody = (f: SshRequestProfileFormState): UpdateSshRequestProfileBody => ({
    name: f.name,
    description: f.description,
    allowedSshSigningProfileIds: JSON.stringify(f.allowedSshSigningProfileIds),
    allowedSshCertProfileIds: JSON.stringify(f.allowedSshCertProfileIds),
    requireApproval: f.requireApproval,
    maxValidityHours: hoursOrDefault(f.maxValidityHours),
    certificateAuthorityId: textOrNull(f.certificateAuthorityId),
});

/** True when an edit would unbind a CA-bound profile, which the update endpoint cannot do. */
export const unbindsCa = (f: SshRequestProfileFormState, mode: ProfileFormMode): boolean =>
    mode === 'edit' && !!f.boundCertificateAuthorityId && !f.certificateAuthorityId;

export const UNBIND_REASON = 'A CA-bound SSH request profile cannot be changed to Any CA; choose a CA, or create a new profile without one.';

/** Why Save is blocked; empty when the form may be saved. */
export const validate = (f: SshRequestProfileFormState, mode: ProfileFormMode): string[] => {
    const reasons: string[] = [];
    if (!f.name) reasons.push(NAME_REQUIRED_REASON);
    if (unbindsCa(f, mode)) reasons.push(UNBIND_REASON);
    return reasons;
};
