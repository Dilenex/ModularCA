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
import { type TypedEntry, hasTypedEntryProblems } from '@shared/components/typedEntryList';
import { SAN_RESTRICTION_TYPES, SUBJECT_RESTRICTION_TYPES, restrictionFromRows } from './enrollmentRestriction';
import { can, canAtSpace, consoleCas, spacesOf, type EffectiveCapabilities } from '../authz';
import type { Scope } from '../scope';

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
    /** Rows of DNS domains and DN attributes; one restriction string on the wire. */
    subjectRestriction: TypedEntry[];
    /** Rows of DNS domains. */
    sanRestriction: TypedEntry[];
    referenceValue: string;
    signingProfileId: string;
    /** Where a token is accepted: a {@link TokenScopeOption} value, or empty when not chosen. */
    tokenScope: string;
}

/** A blank form. Expiry defaults to a day for tokens; CMP overrides to 30 days when selected. */
export function emptyEnrollmentForm(tokenScope = ''): EnrollmentFormState {
    return {
        protocol: '',
        expiresInHours: 24,
        maxUses: 1,
        subjectRestriction: [],
        sanRestriction: [],
        referenceValue: '',
        signingProfileId: '',
        tokenScope,
    };
}

/** A place a token can be accepted, as the scope select offers it. */
export interface TokenScopeOption {
    /** `instance`, `space:<id>` or `ca:<id>`. */
    value: string;
    label: string;
    group: 'Instance' | 'Spaces' | 'CAs';
    /** The CAs the token would be accepted at, which the signing profiles are filtered to. */
    caIds: string[];
}

/**
 * The places a token can be accepted from the console's current scope, among those the caller
 * holds cert.revoke across: under all CAs, the instance's CAs, each space and each CA; under a
 * space, the space and its CAs; under a CA, that CA. SSH CAs take no enrollment tokens.
 */
export function tokenScopeOptions(scope: Scope, caps: EffectiveCapabilities | null | undefined): TokenScopeOption[] {
    const cas = consoleCas(caps).filter(ca => !ca.isSshCa && can(caps, 'cert.revoke', ca.id));
    const caOption = (ca: typeof cas[number]): TokenScopeOption => ({
        value: `ca:${ca.id}`, label: ca.spaceId ? `${ca.label} (${ca.spaceName || ca.spaceSlug})` : ca.label, group: 'CAs', caIds: [ca.id],
    });
    const spaceOption = (space: { id: string; name: string }): TokenScopeOption => ({
        value: `space:${space.id}`, label: `${space.name}: any of its CAs`, group: 'Spaces', caIds: cas.filter(ca => ca.spaceId === space.id).map(ca => ca.id),
    });
    switch (scope.kind) {
        case 'all': {
            const instance: TokenScopeOption[] = can(caps, 'cert.revoke')
                ? [{ value: 'instance', label: 'CAs not in a space', group: 'Instance', caIds: cas.filter(ca => ca.spaceId == null).map(ca => ca.id) }]
                : [];
            const spaces = spacesOf(caps).filter(s => canAtSpace(caps, 'cert.revoke', s.id)).map(spaceOption);
            return [...instance, ...spaces, ...cas.map(caOption)];
        }
        case 'space': {
            const space = canAtSpace(caps, 'cert.revoke', scope.spaceId) ? [spaceOption({ id: scope.spaceId, name: scope.name })] : [];
            return [...space, ...cas.filter(ca => ca.spaceId === scope.spaceId).map(caOption)];
        }
        case 'ca':
            return cas.filter(ca => ca.id === scope.caId).map(caOption);
        case 'mine':
            return [];
    }
}

/** The scope the form starts on: the view's own space or CA when it is offered, or the only option. */
export function defaultTokenScope(scope: Scope, options: TokenScopeOption[]): string {
    const own = scope.kind === 'space' ? `space:${scope.spaceId}` : scope.kind === 'ca' ? `ca:${scope.caId}` : null;
    if (own && options.some(o => o.value === own)) return own;
    return options.length === 1 ? options[0].value : '';
}

/** Where a stored token or credential is accepted, by the CA label or space name the caller can see. */
export function tokenAcceptedAt(
    row: { certificateAuthorityId?: string | null; spaceId?: string | null },
    cas: { id: string; label: string }[], spaces: { id: string; name: string }[],
): string {
    if (row.certificateAuthorityId) return cas.find(c => c.id === row.certificateAuthorityId)?.label ?? `CA ${row.certificateAuthorityId.slice(0, 8)}…`;
    if (row.spaceId) return `${spaces.find(s => s.id === row.spaceId)?.name ?? `Space ${row.spaceId.slice(0, 8)}…`}: any of its CAs`;
    return 'CAs not in a space';
}

/** The `scope` and `scopeId` a token scope value sends, or nulls when none is chosen. */
export function tokenScopeRequest(value: string): { scope: 'Instance' | 'Space' | 'Ca' | null; scopeId: string | null } {
    if (value === 'instance') return { scope: 'Instance', scopeId: null };
    if (value.startsWith('space:')) return { scope: 'Space', scopeId: value.slice('space:'.length) };
    if (value.startsWith('ca:')) return { scope: 'Ca', scopeId: value.slice('ca:'.length) };
    return { scope: null, scopeId: null };
}

/**
 * The signing profiles a token in `option` can carry: those issued by one of its CAs, plus those
 * bound to no CA. `caIdOfIssuer` maps a profile's issuer (a CA certificate id) to the CA id.
 */
export function signingProfilesForTokenScope<P extends { issuerId?: string | null }>(
    profiles: P[], option: TokenScopeOption | undefined, caIdOfIssuer: (issuerId: string) => string | undefined,
): P[] {
    if (!option) return [];
    return profiles.filter(p => {
        if (!p.issuerId) return true;
        const caId = caIdOfIssuer(p.issuerId);
        return !!caId && option.caIds.includes(caId);
    });
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

    if (kind === 'token' && !form.tokenScope) return TOKEN_SCOPE_REASON;

    if (kind === 'token' && (
        hasTypedEntryProblems(form.subjectRestriction, SUBJECT_RESTRICTION_TYPES)
        || hasTypedEntryProblems(form.sanRestriction, SAN_RESTRICTION_TYPES, { allowedTypes: ['DNS'] }))) {
        return RESTRICTIONS_REASON;
    }

    return null;
}

export const RESTRICTIONS_REASON = 'Fix the restrictions marked above.';
export const TOKEN_SCOPE_REASON = 'Choose where the token is accepted.';

/**
 * The POST body for the bearer-token endpoint. Only called for token-kind protocols. The chosen
 * scope decides where the token is accepted; the signing profile is optional and must issue from
 * inside it.
 */
export function buildTokenRequest(form: EnrollmentFormState): Record<string, unknown> {
    return {
        ...tokenScopeRequest(form.tokenScope),
        signingProfileId: form.signingProfileId || null,
        expiresInHours: form.expiresInHours || null,
        maxUses: form.maxUses || 0,
        subjectRestriction: restrictionFromRows(form.subjectRestriction) || null,
        sanRestriction: restrictionFromRows(form.sanRestriction) || null,
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
