/**
 * The protocol catalog and field logic behind the single enrollment-credential form.
 *
 * The page used to carry two buttons and two independent forms — "Generate Token" and "Create
 * CMP Credential" — because CMP produces a reference value and a shared secret rather than a
 * bearer token. That split put the choice of protocol after the choice of button, so an operator
 * had to know which button a protocol lived behind before selecting it. One button, one required
 * protocol selector, and the fields that follow from the protocol reads the way an operator
 * thinks: pick what you are enrolling, then fill in what that needs.
 *
 * Kept as pure data and functions so the branching is testable without rendering the page.
 */

/** How a chosen protocol is created and what it hands back. */
export type EnrollmentKind =
    /** A bearer token. QR additionally shows an enrollment URL and QR image. */
    | 'token'
    /** A CMP shared-secret credential: a reference value and a secret, via a different endpoint. */
    | 'cmp';

export interface EnrollmentProtocol {
    /** The value stored and sent. For token kinds it is also the token's Protocol restriction. */
    value: string;
    /** What the operator sees in the selector. */
    label: string;
    kind: EnrollmentKind;
    /** One line under the selector explaining what this produces. */
    description: string;
}

/**
 * The protocols an operator can create a credential for, in the order they appear in the selector.
 *
 * QR leads because it is the one that needs no client tooling — a person scans it. EST and SCEP
 * are the same bearer-token shape with a protocol restriction. CMP is last because it is the odd
 * one: a shared secret, not a token.
 */
export const ENROLLMENT_PROTOCOLS: readonly EnrollmentProtocol[] = [
    { value: 'QR', label: 'Public enrollment page (QR)', kind: 'token', description: 'A one-time link and QR code that opens a browser page for pasting a CSR. No client software needed.' },
    { value: 'EST', label: 'EST', kind: 'token', description: 'A bearer token an EST client presents. The account behind HTTP Basic still needs cert.request on the CA.' },
    { value: 'SCEP', label: 'SCEP', kind: 'token', description: 'A bearer token used as the SCEP challenge password.' },
    { value: 'CMP', label: 'CMP (shared secret)', kind: 'cmp', description: 'A reference value and shared secret for PBMAC-protected CMP. Scoped to one CA by its signing profile.' },
];

/** The catalog entry for a protocol value, or undefined when nothing is selected or it is unknown. */
export function enrollmentProtocolMeta(value: string | null | undefined): EnrollmentProtocol | undefined {
    if (!value) return undefined;
    return ENROLLMENT_PROTOCOLS.find(p => p.value === value);
}

/** The kind for a protocol value, or null when nothing valid is selected. */
export function enrollmentKind(value: string | null | undefined): EnrollmentKind | null {
    return enrollmentProtocolMeta(value)?.kind ?? null;
}

/** Whether the result panel should show the enrollment URL and QR image. Only the QR protocol. */
export function showsQrResult(value: string | null | undefined): boolean {
    return value === 'QR';
}

export interface EnrollmentFormState {
    protocol: string;
    expiresInHours: number | '';
    maxUses: number | '';
    subjectRestriction: string;
    sanRestriction: string;
    referenceValue: string;
    signingProfileId: string;
}

/** A blank form. Expiry defaults to a day for tokens; CMP overrides to 30 days when selected. */
export function emptyEnrollmentForm(): EnrollmentFormState {
    return {
        protocol: '',
        expiresInHours: 24,
        maxUses: 1,
        subjectRestriction: '',
        sanRestriction: '',
        referenceValue: '',
        signingProfileId: '',
    };
}

/**
 * Validates the form for the selected protocol. Returns the first problem, or null when it is
 * ready to submit. Reference-value character rules are delegated to the caller so this file does
 * not duplicate them.
 */
export function validateEnrollmentForm(
    form: EnrollmentFormState,
    validateReference: (v: string) => string | null,
): string | null {
    const kind = enrollmentKind(form.protocol);
    if (kind === null) return 'Choose a protocol.';

    if (kind === 'cmp') {
        const refError = validateReference(form.referenceValue);
        if (refError) return refError;
        if (!form.signingProfileId) return 'Choose the signing profile; it decides which CA the credential belongs to.';
    }

    return null;
}

/** The POST body for the bearer-token endpoint. Only called for token-kind protocols. */
export function buildTokenRequest(form: EnrollmentFormState): Record<string, unknown> {
    return {
        expiresInHours: form.expiresInHours || null,
        maxUses: form.maxUses || 0,
        subjectRestriction: form.subjectRestriction || null,
        sanRestriction: form.sanRestriction || null,
        protocol: form.protocol,
    };
}

/** The POST body for the CMP shared-secret endpoint. Only called for the CMP protocol. */
export function buildCmpRequest(form: EnrollmentFormState): Record<string, unknown> {
    return {
        referenceValue: form.referenceValue.trim(),
        signingProfileId: form.signingProfileId,
        expiresInHours: form.expiresInHours || null,
        maxUses: form.maxUses || 0,
    };
}
