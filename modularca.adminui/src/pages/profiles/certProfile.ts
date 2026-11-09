import type { CreateCertProfileRequest, UpdateCertProfileRequest } from '@shared/generated';
import {
    type EkuVocabulary, type ProfileFormMode, DEFAULT_EKU_VOCABULARY, KEY_USAGE_OPTIONS,
    INHERITANCE_REASON, NAME_REQUIRED_REASON, canonicalizeUsages, inheritancePairInconsistent,
    parseListField, textOrNull,
} from './profileFormCore';
import { type KeyPolicyState, blockingProblems, fromEditorState, toEditorState } from './keyPolicy';
import { type CeilingMode, ceilingEmptyOnly, ceilingListOut, ceilingModeFromList } from '@shared/components/checkboxListModel';
import { type CtLogChoice, ctLogIdsFromStored, ctLogIdsToBody, unknownCtLogIds } from './ctLogChoices';
import { periodText } from '@shared/periodText';

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
    /** Expiry warning: percents as typed ('' for the parent's value or the default), windows as ISO 8601 ('' for no cap). */
    expiryWarningPercent: string;
    expiryWarningMaxWindow: string;
    expiryAlertPercent: string;
    expiryAlertMaxWindow: string;
    expiryNeverWarn: boolean;
    expiryWarningOverridesParent: boolean;
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
    expiryWarningPercent: '', expiryWarningMaxWindow: '', expiryAlertPercent: '', expiryAlertMaxWindow: '',
    expiryNeverWarn: false, expiryWarningOverridesParent: false,
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
        expiryWarningPercent: p?.expiryWarningPercent == null ? '' : String(p.expiryWarningPercent),
        expiryWarningMaxWindow: p?.expiryWarningMaxWindow || '',
        expiryAlertPercent: p?.expiryAlertPercent == null ? '' : String(p.expiryAlertPercent),
        expiryAlertMaxWindow: p?.expiryAlertMaxWindow || '',
        expiryNeverWarn: !!p?.expiryNeverWarn,
        expiryWarningOverridesParent: !!p?.expiryWarningOverridesParent,
    };
};

/** A typed percent as the body carries it: null when blank, otherwise the number (validate refuses anything else). */
const percentOrNull = (s: string): number | null => (s.trim() === '' ? null : Number(s.trim()));

const ISO_PERIOD = /^P(?!$)(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?!$)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/;

/**
 * `ms` moved by `months` calendar months in UTC, as .NET's DateTime.AddMonths does it: the day of
 * the month is kept, or pulled back to the target month's last day when that month is shorter.
 */
function addMonthsUtc(ms: number, months: number): number {
    if (months === 0) return ms;
    const d = new Date(ms);
    const total = d.getUTCMonth() + months;
    const year = d.getUTCFullYear() + Math.floor(total / 12);
    const month = ((total % 12) + 12) % 12;
    const lastDay = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
    return Date.UTC(year, month, Math.min(d.getUTCDate(), lastDay),
        d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), d.getUTCMilliseconds());
}

/**
 * An ISO 8601 duration in milliseconds, measured from `now` the way the server measures it
 * (Iso8601ParserUtil): years, then months, as calendar steps from now in UTC, then weeks, days and
 * time. A month is therefore 28 to 31 days depending on the date, so P30D against P1M compares as
 * the server would compare it on save; null when the text is not such a duration.
 */
export function isoWindowMs(iso: string, now: Date = new Date()): number | null {
    const m = ISO_PERIOD.exec(iso.trim());
    if (!m) return null;
    const n = (i: number) => (m[i] ? parseInt(m[i], 10) : 0);
    const start = now.getTime();
    const calendar = addMonthsUtc(start, n(1) * 12 + n(2));
    return calendar - start + (n(3) * 7 + n(4)) * 86_400_000 + n(5) * 3_600_000 + n(6) * 60_000 + n(7) * 1000;
}

/**
 * One level of a profile's expiry warning in words: "30 % of lifetime left (default)", "20 % of
 * lifetime left, at most 30 days ahead", or for a CA profile that sets nothing, the fixed window.
 */
export function expiryLevelText(percent: number | null | undefined, maxWindow: string | null | undefined, defaultPercent: number, caDays: number | null): string {
    if (percent == null && !maxWindow && caDays !== null) return `${caDays} days before expiry (CA default)`;
    const pct = percent == null ? `${defaultPercent} % of lifetime left (default)` : `${percent} % of lifetime left`;
    return maxWindow ? `${pct}, at most ${periodText(maxWindow)} ahead` : pct;
}

/** A profile's (or a resolved profile's) soft warning, in words. */
export const expiryWarningText = (p: any): string => p?.expiryNeverWarn ? 'Never: renewed automatically'
    : expiryLevelText(p?.expiryWarningPercent, p?.expiryWarningMaxWindow, 30, p?.isCaProfile ? 30 : null);

/** A profile's (or a resolved profile's) alert, in words. */
export const expiryAlertText = (p: any): string => p?.expiryNeverWarn ? 'Never: renewed automatically'
    : expiryLevelText(p?.expiryAlertPercent, p?.expiryAlertMaxWindow, 10, p?.isCaProfile ? 7 : null);

export const EXPIRY_PERCENT_REASON = 'The expiry warning and alert percents must be whole numbers from 1 to 100.';
export const EXPIRY_ORDER_REASON = 'The expiry alert percent cannot be larger than the warning percent: the alert comes after the warning.';
export const EXPIRY_WINDOW_REASON = 'The expiry warning and alert windows must be ISO 8601 durations longer than zero, such as P30D or PT6H.';
export const EXPIRY_WINDOW_ORDER_REASON = 'The expiry alert window cannot be longer than the warning window.';

/**
 * Why the expiry warning settings cannot be saved, as the server checks them (MCA-PRF-001). Windows
 * are compared as measured from `now`, as the server measures them when it saves.
 */
export const expiryProblems = (f: Pick<CertProfileFormState, 'expiryWarningPercent' | 'expiryWarningMaxWindow' | 'expiryAlertPercent' | 'expiryAlertMaxWindow'>, now: Date = new Date()): string[] => {
    const reasons: string[] = [];
    const pct = (s: string) => s.trim() === '' || (/^\d+$/.test(s.trim()) && Number(s) >= 1 && Number(s) <= 100);
    if (!pct(f.expiryWarningPercent) || !pct(f.expiryAlertPercent)) reasons.push(EXPIRY_PERCENT_REASON);
    else {
        const w = percentOrNull(f.expiryWarningPercent), a = percentOrNull(f.expiryAlertPercent);
        if (w !== null && a !== null && a > w) reasons.push(EXPIRY_ORDER_REASON);
    }
    const win = (s: string) => (s.trim() === '' ? undefined : isoWindowMs(s, now));
    const ww = win(f.expiryWarningMaxWindow), aw = win(f.expiryAlertMaxWindow);
    if (ww === null || ww === 0 || aw === null || aw === 0) reasons.push(EXPIRY_WINDOW_REASON);
    else if (ww !== undefined && aw !== undefined && aw > ww) reasons.push(EXPIRY_WINDOW_ORDER_REASON);
    return reasons;
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
        expiryWarningPercent: percentOrNull(f.expiryWarningPercent),
        expiryWarningMaxWindow: textOrNull(f.expiryWarningMaxWindow.trim()),
        expiryAlertPercent: percentOrNull(f.expiryAlertPercent),
        expiryAlertMaxWindow: textOrNull(f.expiryAlertMaxWindow.trim()),
        expiryNeverWarn: f.expiryNeverWarn,
        expiryWarningOverridesParent: f.expiryWarningOverridesParent,
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
    reasons.push(...expiryProblems(f));
    return reasons;
};
