import { validateRegex } from '@shared/validators';
import { invalidItems } from '@shared/components/chipList';
import {
    type ProfileFormMode, NAME_REQUIRED_REASON, parseJsonArray, sshRequiredNotAllowed, textOrNull,
} from './profileFormCore';
import { hoursOrDefault } from './sshSigningProfile';
import { type CeilingMode, ceilingEmptyOnly, ceilingListOut, ceilingModeFromList } from '@shared/components/checkboxListModel';

/**
 * Form model for an SSH cert profile, shared by /profiles/ssh-cert/new and /profiles/ssh-cert/:id.
 * The DTOs live in AdminSshProfileController.cs and are not generated; the update DTO is a patch
 * (null leaves a value alone), so the update body sends Description as a string to let it clear.
 */

/** Mirrors CreateSshCertProfileRequest in AdminSshProfileController.cs. */
export interface CreateSshCertProfileBody {
    name: string;
    description: string | null;
    allowedPrincipalPatterns: string | null;
    maxPrincipals: number | null;
    allowedExtensions: string | null;
    requiredExtensions: string | null;
    maxValidityHours: number | null;
}

/** Mirrors UpdateSshCertProfileRequest in AdminSshProfileController.cs (every member optional). */
export interface UpdateSshCertProfileBody {
    name: string | null;
    description: string | null;
    allowedPrincipalPatterns: string | null;
    maxPrincipals: number | null;
    allowedExtensions: string | null;
    requiredExtensions: string | null;
    maxValidityHours: number | null;
}

export interface SshCertProfileFormState {
    name: string;
    description: string;
    /** A JSON array on the wire. */
    allowedPrincipalPatterns: string[];
    maxPrincipals: string;
    allowedExtensions: string[];
    /** Any saves an empty list (unrestricted); Only these saves the list. */
    allowedExtensionsMode: CeilingMode;
    requiredExtensions: string[];
    maxValidityHours: string;
}

export const DEFAULT_MAX_PRINCIPALS = 10;

/** The server's create default for AllowedExtensions. */
export const DEFAULT_ALLOWED_EXTENSIONS = ['permit-pty', 'permit-port-forwarding', 'permit-agent-forwarding', 'permit-X11-forwarding', 'permit-user-rc'];

/** The form for a new SSH cert profile; the defaults are the server's create defaults. */
export const emptyForm = (): SshCertProfileFormState => ({
    name: '', description: '', allowedPrincipalPatterns: [],
    maxPrincipals: String(DEFAULT_MAX_PRINCIPALS),
    allowedExtensions: [...DEFAULT_ALLOWED_EXTENSIONS], allowedExtensionsMode: 'only', requiredExtensions: [],
    maxValidityHours: '720',
});

/** Seeds the form from a stored profile. */
export const formFromProfile = (p: any): SshCertProfileFormState => ({
    name: p?.name || '',
    description: p?.description || '',
    allowedPrincipalPatterns: parseJsonArray(p?.allowedPrincipalPatterns),
    maxPrincipals: String(p?.maxPrincipals ?? DEFAULT_MAX_PRINCIPALS),
    allowedExtensions: parseJsonArray(p?.allowedExtensions),
    allowedExtensionsMode: ceilingModeFromList(parseJsonArray(p?.allowedExtensions)),
    requiredExtensions: parseJsonArray(p?.requiredExtensions),
    maxValidityHours: String(p?.maxValidityHours ?? 720),
});

/** The Allowed Extensions list as saved: empty (unrestricted) in Any mode. */
export const effectiveAllowed = (f: SshCertProfileFormState): string[] => ceilingListOut(f.allowedExtensionsMode, f.allowedExtensions);

const sharedBody = (f: SshCertProfileFormState) => ({
    allowedPrincipalPatterns: JSON.stringify(f.allowedPrincipalPatterns),
    maxPrincipals: parseInt(f.maxPrincipals, 10) || DEFAULT_MAX_PRINCIPALS,
    allowedExtensions: JSON.stringify(effectiveAllowed(f)),
    requiredExtensions: JSON.stringify(f.requiredExtensions),
    maxValidityHours: hoursOrDefault(f.maxValidityHours),
});

export const formToCreateBody = (f: SshCertProfileFormState): CreateSshCertProfileBody => ({
    name: f.name,
    description: textOrNull(f.description),
    ...sharedBody(f),
});

export const formToUpdateBody = (f: SshCertProfileFormState): UpdateSshCertProfileBody => ({
    name: f.name,
    description: f.description,
    ...sharedBody(f),
});

export const PRINCIPAL_PATTERN_REASON = 'Fix the login name patterns marked invalid; each must be a regular expression that compiles.';

/** How one pattern treats a test principal: matched, not matched, or the pattern does not compile. */
export interface PatternMatch {
    pattern: string;
    result: 'match' | 'no-match' | 'invalid';
}

/**
 * Runs a test principal against each pattern, as the signing endpoints do: a principal is allowed
 * when any pattern matches it. Uses the browser's regex engine; the server uses .NET's.
 */
export const matchPrincipal = (principal: string, patterns: string[]): PatternMatch[] =>
    patterns.map((pattern): PatternMatch => {
        try { return { pattern, result: new RegExp(pattern).test(principal) ? 'match' : 'no-match' }; }
        catch { return { pattern, result: 'invalid' }; }
    });

export const ALLOWED_EXTENSIONS_EMPTY_REASON = 'Allowed Extensions is set to Only these with nothing ticked, which would save as unrestricted. Tick at least one extension, or choose Any extension.';
export const REQUIRED_NOT_ALLOWED_REASON = 'Every required extension must also be allowed; fix the two pickers below.';

/** Why Save is blocked; empty when the form may be saved. */
export const validate = (f: SshCertProfileFormState, _mode: ProfileFormMode): string[] => {
    const reasons: string[] = [];
    if (!f.name) reasons.push(NAME_REQUIRED_REASON);
    // An empty Allowed list is unrestricted (SshExtensionPolicy.Validate), so it conflicts with nothing.
    if (ceilingEmptyOnly(f.allowedExtensionsMode, f.allowedExtensions)) reasons.push(ALLOWED_EXTENSIONS_EMPTY_REASON);
    if (sshRequiredNotAllowed(f.requiredExtensions, effectiveAllowed(f)).length > 0) reasons.push(REQUIRED_NOT_ALLOWED_REASON);
    if (invalidItems(f.allowedPrincipalPatterns, validateRegex).length > 0) reasons.push(PRINCIPAL_PATTERN_REASON);
    return reasons;
};
