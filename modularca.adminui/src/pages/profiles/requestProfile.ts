import type { CreateRequestProfileRequest, UpdateRequestProfileRequest } from '@shared/generated';
import { emptyRules, parseRules, serializeRules, type RequestProfileRules } from '../../components/requestProfileRules';
import {
    type ProfileFormMode, INHERITANCE_REASON, NAME_REQUIRED_REASON, inheritancePairInconsistent, textOrNull,
} from './profileFormCore';

/**
 * Form model for an enrollment request profile, shared by /profiles/request/new and
 * /profiles/request/:id. Every field is settable on both create and update.
 */
export interface RequestProfileFormState {
    name: string;
    description: string;
    requireApproval: boolean;
    defaultCertProfileId: string;
    rules: RequestProfileRules;
    allowedCertProfileIds: string[];
    inheritsFromId: string;
    inheritanceEnabled: boolean;
    certificateAuthorityId: string;
}

/** The form for a new request profile. */
export const emptyForm = (): RequestProfileFormState => ({
    name: '', description: '', requireApproval: false, defaultCertProfileId: '',
    rules: emptyRules(), allowedCertProfileIds: [],
    inheritsFromId: '', inheritanceEnabled: false, certificateAuthorityId: '',
});

/** Seeds the form from a stored profile. */
export const formFromProfile = (p: any): RequestProfileFormState => ({
    name: p?.name || '',
    description: p?.description || '',
    requireApproval: !!p?.requireApproval,
    defaultCertProfileId: p?.defaultCertProfileId || '',
    rules: parseRules(p),
    allowedCertProfileIds: Array.isArray(p?.allowedCertProfileIds) ? p.allowedCertProfileIds.map(String) : [],
    inheritsFromId: p?.inheritsFromId || '',
    inheritanceEnabled: !!p?.inheritanceEnabled,
    certificateAuthorityId: p?.certificateAuthorityId || '',
});

/**
 * The request body for POST and PUT alike; the two DTOs are the same class. The rules go through
 * serializeRules so the editor's '' placeholders never reach the API as match-nothing patterns.
 */
export const formToBody = (f: RequestProfileFormState): CreateRequestProfileRequest => {
    const { subjectDnRules, sanRules } = serializeRules(f.rules);
    return {
        name: f.name,
        description: textOrNull(f.description),
        subjectDnRules,
        sanRules,
        allowedCertProfileIds: [...f.allowedCertProfileIds],
        defaultCertProfileId: textOrNull(f.defaultCertProfileId),
        requireApproval: f.requireApproval,
        certificateAuthorityId: textOrNull(f.certificateAuthorityId),
        inheritsFromId: textOrNull(f.inheritsFromId),
        inheritanceEnabled: f.inheritanceEnabled,
    };
};

export const formToCreateBody: (f: RequestProfileFormState) => CreateRequestProfileRequest = formToBody;
export const formToUpdateBody: (f: RequestProfileFormState) => UpdateRequestProfileRequest = formToBody;

/**
 * Why Save is blocked; empty when the form may be saved. Rules JSON is checked in the rules
 * editor's paste dialog before it reaches the form, so the form never holds unparseable rules.
 */
export const validate = (f: RequestProfileFormState, _mode: ProfileFormMode): string[] => {
    const reasons: string[] = [];
    if (!f.name) reasons.push(NAME_REQUIRED_REASON);
    if (inheritancePairInconsistent(f.inheritsFromId, f.inheritanceEnabled)) reasons.push(INHERITANCE_REASON);
    return reasons;
};
