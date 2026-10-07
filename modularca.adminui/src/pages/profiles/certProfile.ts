import type { CreateCertProfileRequest, UpdateCertProfileRequest } from '@shared/generated';
import {
    type EkuVocabulary, type ProfileFormMode, DEFAULT_EKU_VOCABULARY, KEY_USAGE_OPTIONS,
    INHERITANCE_REASON, NAME_REQUIRED_REASON, canonicalizeUsages, inheritancePairInconsistent,
    parseListField, textOrNull,
} from './profileFormCore';
import { type KeyPolicyState, blockingProblems, fromEditorState, toEditorState } from './keyPolicy';
import { type CeilingMode, ceilingEmptyOnly, ceilingListOut, ceilingModeFromList } from '@shared/components/checkboxListModel';
import { type CtLogChoice, ctLogIdsFromStored, ctLogIdsToBody, unknownCtLogIds } from './ctLogChoices';

/**
 * Form model for a certificate profile, shared by /profiles/cert/new and /profiles/cert/:id.
 * Every field is settable on both create and update (UpdateCertProfileRequest extends the create
 * DTO and CertProfileService.UpdateAsync assigns all of them), so there are no create-only fields.
 */
export interface CertProfileFormState {
    name: string;
    description: string;
    isCaProfile: boolean;
    keyUsages: string[];
    extendedKeyUsages: string[];
    /** AllowedKeyAlgorithms, AllowedKeySizes and AllowedSignatureAlgorithms, edited together. */
    keyPolicy: KeyPolicyState;
    validityPeriodMin: string;
    validityPeriodMax: string;
    ctEnabled: boolean;
    /** Internal CT log ids; a JSON array on the wire, null when none. */
    ctLogIds: string[];
    /** Every enabled log (saves null) or only the ticked ones. */
    ctLogsMode: CeilingMode;
    /**
     * The stored value was an empty JSON array. Every enabled log then saves `[]` again rather than
     * null: the resolver treats `[]` on a child as an override of its parent's list, null as inherit.
     */
    ctLogsStoredEmptyArray: boolean;
    inheritsFromId: string;
    inheritanceEnabled: boolean;
    certificateAuthorityId: string;
    allowWildcard: boolean;
}

/** The form for a new certificate profile. */
export const emptyForm = (): CertProfileFormState => ({
    name: '', description: '', isCaProfile: false,
    keyUsages: [], extendedKeyUsages: [],
    keyPolicy: toEditorState({}),
    validityPeriodMin: '', validityPeriodMax: '',
    ctEnabled: false, ctLogIds: [], ctLogsMode: 'any', ctLogsStoredEmptyArray: false,
    inheritsFromId: '', inheritanceEnabled: false, certificateAuthorityId: '',
    allowWildcard: false,
});

/**
 * Seeds the form from a stored profile. Usages are canonicalised rather than just parsed, so rows
 * holding labels or JSON fragments show their real selection and the next save rewrites them
 * cleanly. The three key ceilings go through parseListField so a comma-separated value written by
 * policy sync is not read as empty and then saved back as unrestricted.
 */
export const formFromProfile = (p: any, eku: EkuVocabulary = DEFAULT_EKU_VOCABULARY): CertProfileFormState => {
    const ctLogIds = ctLogIdsFromStored(p?.ctLogIds);
    return {
        name: p?.name || '',
        description: p?.description || '',
        isCaProfile: !!p?.isCaProfile,
        keyUsages: canonicalizeUsages(parseListField(p?.keyUsages), KEY_USAGE_OPTIONS),
        extendedKeyUsages: canonicalizeUsages(parseListField(p?.extendedKeyUsages), eku.options, eku.aliases),
        keyPolicy: toEditorState({
            algorithms: parseListField(p?.allowedKeyAlgorithms),
            sizes: parseListField(p?.allowedKeySizes),
            signatures: parseListField(p?.allowedSignatureAlgorithms),
        }),
        validityPeriodMin: p?.validityPeriodMin || '',
        validityPeriodMax: p?.validityPeriodMax || '',
        ctEnabled: !!p?.ctEnabled,
        ctLogIds,
        ctLogsMode: ceilingModeFromList(ctLogIds),
        ctLogsStoredEmptyArray: typeof p?.ctLogIds === 'string' && p.ctLogIds.replace(/\s/g, '') === '[]',
        inheritsFromId: p?.inheritsFromId || '',
        inheritanceEnabled: !!p?.inheritanceEnabled,
        certificateAuthorityId: p?.certificateAuthorityId || '',
        allowWildcard: !!p?.allowWildcard,
    };
};

/** The request body for POST and PUT alike; the two DTOs are the same class. */
export const formToBody = (f: CertProfileFormState): CreateCertProfileRequest => {
    const keys = fromEditorState(f.keyPolicy);
    return {
        name: f.name,
        description: f.description,
        isCaProfile: f.isCaProfile,
        keyUsages: f.keyUsages.join(', '),
        extendedKeyUsages: f.extendedKeyUsages.join(', '),
        validityPeriodMin: textOrNull(f.validityPeriodMin),
        validityPeriodMax: textOrNull(f.validityPeriodMax),
        allowedKeyAlgorithms: JSON.stringify(keys.algorithms),
        allowedKeySizes: JSON.stringify(keys.sizes),
        allowedSignatureAlgorithms: JSON.stringify(keys.signatures),
        certificateAuthorityId: textOrNull(f.certificateAuthorityId),
        inheritsFromId: textOrNull(f.inheritsFromId),
        inheritanceEnabled: f.inheritanceEnabled,
        allowWildcard: f.allowWildcard,
        ctEnabled: f.ctEnabled,
        ctLogIds: f.ctLogsMode === 'any' && f.ctLogsStoredEmptyArray ? '[]' : ctLogIdsToBody(ceilingListOut(f.ctLogsMode, f.ctLogIds)),
    };
};

export const formToCreateBody: (f: CertProfileFormState) => CreateCertProfileRequest = formToBody;
export const formToUpdateBody: (f: CertProfileFormState) => UpdateCertProfileRequest = formToBody;

export const CT_LOGS_EMPTY_REASON = 'CT Logs is set to Only these logs with nothing ticked, which would save as every enabled log. Tick at least one log, or choose Every enabled log.';
export const CT_LOGS_UNKNOWN_REASON = 'Remove the unknown CT logs marked below; the server refuses ids that name no log.';

export const KEY_POLICY_REASON = 'Fix the keys and signatures marked in red below; as they stand they would save as no restriction.';

/**
 * Why Save is blocked; empty when the form may be saved. With the CT log catalog (null when it
 * could not be loaded), stored ids naming no log block Save, since the server refuses them.
 */
export const validate = (f: CertProfileFormState, _mode: ProfileFormMode, ctLogs: readonly CtLogChoice[] | null = null): string[] => {
    const reasons: string[] = [];
    if (!f.name) reasons.push(NAME_REQUIRED_REASON);
    if (inheritancePairInconsistent(f.inheritsFromId, f.inheritanceEnabled)) reasons.push(INHERITANCE_REASON);
    if (blockingProblems(f.keyPolicy).length > 0) reasons.push(KEY_POLICY_REASON);
    if (f.ctEnabled && ceilingEmptyOnly(f.ctLogsMode, f.ctLogIds)) reasons.push(CT_LOGS_EMPTY_REASON);
    if (unknownCtLogIds(ceilingListOut(f.ctLogsMode, f.ctLogIds), ctLogs).length > 0) reasons.push(CT_LOGS_UNKNOWN_REASON);
    return reasons;
};
