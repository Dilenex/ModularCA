import type { CreateSigningProfileRequest, UpdateSigningProfileRequest } from '@shared/generated';
import {
    type EkuVocabulary, type ProfileFormMode, DEFAULT_EKU_VOCABULARY, INHERITANCE_REASON, NAME_REQUIRED_REASON,
    canonicalizeUsages, inheritancePairInconsistent, parseListField, textOrNull,
} from './profileFormCore';
import { type CeilingMode, ceilingEmptyOnly, ceilingListOut, ceilingModeFromList } from '@shared/components/checkboxListModel';
import type { TypedEntry } from '@shared/components/typedEntryList';
import { nameConstraintRowsFromStored, nameConstraintRowsInvalid, nameConstraintRowsToJson } from '@shared/generalNames';
import { type PolicyRow, policiesFromStored, policiesToFields, policyRowsInvalid } from './certificatePolicies';

/**
 * Form model for a signing profile, shared by /profiles/signing/new and /profiles/signing/:id.
 * Every field is settable on both create and update; the allowed cert profiles travel in the same
 * body, since SigningProfileService.CreateAsync and UpdateAsync both write the links from it.
 */
export interface SigningProfileFormState {
    name: string;
    description: string;
    isDefault: boolean;
    issuerId: string;
    allowedAlgorithms: string[];
    /** Any saves an empty list (unrestricted); Only these saves the list. */
    allowedAlgorithmsMode: CeilingMode;
    allowedEkus: string[];
    allowedEkusMode: CeilingMode;
    maxPathLength: string;
    /** Rows of the Permitted list; a JSON array of `TYPE:value` on the wire. */
    nameConstraintsPermitted: TypedEntry[];
    nameConstraintsExcluded: TypedEntry[];
    /** The Certificate Policies table; `policyOids` and `policyQualifiersJson` on the wire. */
    policies: PolicyRow[];
    /** Mark the CertificatePolicies extension critical; written as `critical: true` on each qualifier entry. */
    policiesCritical: boolean;
    /** What loading dropped from the stored qualifiers, shown above the table; never sent. */
    policyNotices: string[];
    inhibitAnyPolicy: boolean;
    inheritsFromId: string;
    inheritanceEnabled: boolean;
    extendedKeyUsageCritical: boolean;
    allowedCertProfileIds: string[];
}

/** The form for a new signing profile. */
export const emptyForm = (): SigningProfileFormState => ({
    name: '', description: '', isDefault: false, issuerId: '',
    allowedAlgorithms: [], allowedAlgorithmsMode: 'any', allowedEkus: [], allowedEkusMode: 'any',
    maxPathLength: '', nameConstraintsPermitted: [], nameConstraintsExcluded: [],
    policies: [], policiesCritical: false, policyNotices: [], inhibitAnyPolicy: false,
    inheritsFromId: '', inheritanceEnabled: false,
    extendedKeyUsageCritical: false,
    allowedCertProfileIds: [],
});

/**
 * Seeds the form from a stored profile. The links come from GET .../allowed-cert-profiles when the
 * caller has them, otherwise from the profile row. The wire name is `allowedEKUs` (camelCase
 * lowercases only the leading capital); reading `allowedEkus` alone gave an empty picker that was
 * then saved back over the real list.
 */
export const formFromProfile = (
    p: any,
    eku: EkuVocabulary = DEFAULT_EKU_VOCABULARY,
    allowedCertProfileIds?: string[],
): SigningProfileFormState => {
    const allowedAlgorithms = parseListField(p?.allowedAlgorithms);
    const allowedEkus = canonicalizeUsages(parseListField(p?.allowedEKUs ?? p?.allowedEkus), eku.options, eku.aliases);
    const policies = policiesFromStored(p?.policyOids, p?.policyQualifiersJson);
    return {
        name: p?.name || '',
        description: p?.description || '',
        isDefault: !!p?.isDefault,
        issuerId: p?.issuerId || '',
        allowedAlgorithms,
        allowedAlgorithmsMode: ceilingModeFromList(allowedAlgorithms),
        allowedEkus,
        allowedEkusMode: ceilingModeFromList(allowedEkus),
        maxPathLength: p?.maxPathLength != null ? String(p.maxPathLength) : '',
        nameConstraintsPermitted: nameConstraintRowsFromStored(p?.nameConstraintsPermitted),
        nameConstraintsExcluded: nameConstraintRowsFromStored(p?.nameConstraintsExcluded),
        policies: policies.rows,
        policiesCritical: policies.critical,
        policyNotices: policies.notices,
        inhibitAnyPolicy: !!p?.inhibitAnyPolicy,
        inheritsFromId: p?.inheritsFromId || '',
        inheritanceEnabled: !!p?.inheritanceEnabled,
        extendedKeyUsageCritical: !!p?.extendedKeyUsageCritical,
        allowedCertProfileIds: [...(allowedCertProfileIds ?? (Array.isArray(p?.allowedCertProfileIds) ? p.allowedCertProfileIds : []))].map(String),
    };
};

/** The request body for POST and PUT alike; the two DTOs are the same class. */
export const formToBody = (f: SigningProfileFormState): CreateSigningProfileRequest => {
    const policies = policiesToFields({ rows: f.policies, critical: f.policiesCritical });
    return {
        name: f.name,
        description: f.description,
        allowedAlgorithms: JSON.stringify(ceilingListOut(f.allowedAlgorithmsMode, f.allowedAlgorithms)),
        allowedEKUs: JSON.stringify(ceilingListOut(f.allowedEkusMode, f.allowedEkus)),
        isDefault: f.isDefault,
        issuerId: textOrNull(f.issuerId),
        maxPathLength: f.maxPathLength ? parseInt(f.maxPathLength, 10) : null,
        nameConstraintsPermitted: nameConstraintRowsToJson(f.nameConstraintsPermitted),
        nameConstraintsExcluded: nameConstraintRowsToJson(f.nameConstraintsExcluded),
        policyOids: policies.policyOids,
        inhibitAnyPolicy: f.inhibitAnyPolicy,
        allowedCertProfileIds: [...f.allowedCertProfileIds],
        inheritsFromId: textOrNull(f.inheritsFromId),
        inheritanceEnabled: f.inheritanceEnabled,
        extendedKeyUsageCritical: f.extendedKeyUsageCritical,
        policyQualifiersJson: policies.policyQualifiersJson,
    };
};

export const formToCreateBody: (f: SigningProfileFormState) => CreateSigningProfileRequest = formToBody;
export const formToUpdateBody: (f: SigningProfileFormState) => UpdateSigningProfileRequest = formToBody;

export const ISSUER_REASON = 'Choose an issuing authority; a signing profile without one cannot sign.';
export const POLICIES_REASON = 'Fix the certificate policies marked below; the server refuses an OID or qualifier it cannot encode.';
export const NAME_CONSTRAINTS_REASON = 'Fix the name constraints marked below; the server refuses an entry it cannot encode.';
export const ALGORITHMS_EMPTY_REASON = 'Allowed Algorithms is set to Only these with nothing ticked, which would save as unrestricted. Tick at least one algorithm, or choose Any algorithm.';
export const EKUS_EMPTY_REASON = 'Allowed EKUs is set to Only these with nothing ticked, which would save as unrestricted. Tick at least one EKU, or choose Any EKU.';

/** Why Save is blocked; empty when the form may be saved. */
export const validate = (f: SigningProfileFormState, _mode: ProfileFormMode): string[] => {
    const reasons: string[] = [];
    if (!f.name) reasons.push(NAME_REQUIRED_REASON);
    // The API accepts a null IssuerId, and a signing profile without one cannot sign anything.
    if (!f.issuerId) reasons.push(ISSUER_REASON);
    if (inheritancePairInconsistent(f.inheritsFromId, f.inheritanceEnabled)) reasons.push(INHERITANCE_REASON);
    if (policyRowsInvalid(f.policies)) reasons.push(POLICIES_REASON);
    if (nameConstraintRowsInvalid(f.nameConstraintsPermitted) || nameConstraintRowsInvalid(f.nameConstraintsExcluded)) reasons.push(NAME_CONSTRAINTS_REASON);
    if (ceilingEmptyOnly(f.allowedAlgorithmsMode, f.allowedAlgorithms)) reasons.push(ALGORITHMS_EMPTY_REASON);
    if (ceilingEmptyOnly(f.allowedEkusMode, f.allowedEkus)) reasons.push(EKUS_EMPTY_REASON);
    return reasons;
};
