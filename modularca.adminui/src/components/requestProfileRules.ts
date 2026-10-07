/**
 * The data model behind {@link RequestProfileRulesEditor}: the vocabularies a request profile's
 * rules draw on, and the two conversions between what the API stores and what the editor edits.
 *
 * Separated from the component for the same reason `notifications/notice.ts` is separated from
 * `Toast.tsx`: every decision worth arguing about here — what a legacy row missing its
 * `requirement` should become, whether an empty regex is a pattern or the absence of one — is a
 * pure function that can be tested, rather than a conditional buried in JSX that cannot.
 */

/** DN components offered in the field dropdown. */
export const DN_FIELD_OPTIONS = ['CN', 'O', 'OU', 'L', 'ST', 'C', 'DC'];

export const REQUIREMENT_OPTIONS = ['Required', 'Optional', 'Forbidden'];

/**
 * SAN types a profile may permit.
 *
 * UPN must be selectable or it can never be used: profile validation rejects any SAN whose type is
 * absent from a profile's allowedTypes, on the server and in the browser. It is off by default on
 * every existing profile, which is the intended posture — a UPN asserts an Active Directory
 * identity, so permitting it should be a deliberate per-profile choice.
 */
export const SAN_TYPE_OPTIONS = ['DNS', 'IP', 'Email', 'URI', 'UPN'];

/** Server default for SanTypeRule.MaxCount; mirrored so a new per-type rule starts where the server would. */
export const DEFAULT_SAN_MAX_COUNT = 100;

export interface SubjectDnFieldRule {
    field: string;
    requirement: string;
    fixedValue?: string;
    regex?: string;
    maxLength?: number | null;
    defaultValue?: string;
}

export interface SanTypeRule {
    regex?: string;
    maxCount: number;
}

export interface SanRulesModel {
    allowedTypes: string[];
    required: boolean;
    rules: Record<string, SanTypeRule>;
}

export interface RequestProfileRules {
    subjectDnRules: SubjectDnFieldRule[];
    sanRules: SanRulesModel;
}

export const emptyDnRule = (): SubjectDnFieldRule => ({
    field: 'CN', requirement: 'Required', fixedValue: '', regex: '', maxLength: null, defaultValue: '',
});

export const emptySanRules = (): SanRulesModel => ({
    allowedTypes: ['DNS', 'IP'], required: false, rules: {},
});

export const emptyRules = (): RequestProfileRules => ({
    subjectDnRules: [emptyDnRule()],
    sanRules: emptySanRules(),
});

/**
 * Normalizes whatever the API returned into the shape this editor edits.
 *
 * Deliberately tolerant. These rows were writable as free-form JSON for as long as the edit page
 * shipped a textarea, so a stored profile can legitimately contain a null where an array belongs,
 * a missing `requirement`, or a per-type rule with no `maxCount`. A structured editor that threw on
 * any of those would make the profiles most in need of fixing the ones that cannot be opened.
 */
export function parseRules(profile: { subjectDnRules?: unknown; sanRules?: unknown } | null | undefined): RequestProfileRules {
    const dnSource = Array.isArray(profile?.subjectDnRules) ? profile!.subjectDnRules as any[] : [];
    const subjectDnRules: SubjectDnFieldRule[] = dnSource.map((r: any) => ({
        field: typeof r?.field === 'string' ? r.field : 'CN',
        requirement: REQUIREMENT_OPTIONS.includes(r?.requirement) ? r.requirement : 'Optional',
        fixedValue: typeof r?.fixedValue === 'string' ? r.fixedValue : '',
        regex: typeof r?.regex === 'string' ? r.regex : '',
        maxLength: typeof r?.maxLength === 'number' ? r.maxLength : null,
        defaultValue: typeof r?.defaultValue === 'string' ? r.defaultValue : '',
    }));

    const sanSource = (profile?.sanRules ?? {}) as any;
    const rules: Record<string, SanTypeRule> = {};
    if (sanSource?.rules && typeof sanSource.rules === 'object') {
        for (const [type, rule] of Object.entries<any>(sanSource.rules)) {
            rules[type] = {
                regex: typeof rule?.regex === 'string' ? rule.regex : '',
                maxCount: typeof rule?.maxCount === 'number' ? rule.maxCount : DEFAULT_SAN_MAX_COUNT,
            };
        }
    }

    return {
        subjectDnRules: subjectDnRules.length > 0 ? subjectDnRules : [emptyDnRule()],
        sanRules: {
            allowedTypes: Array.isArray(sanSource?.allowedTypes) ? sanSource.allowedTypes.filter((t: any) => typeof t === 'string') : ['DNS', 'IP'],
            required: !!sanSource?.required,
            rules,
        },
    };
}

/**
 * Strips the editor's empty-string placeholders back to the optional fields the API expects.
 *
 * The inputs above use '' rather than undefined for an unset optional, because a controlled React
 * input with a value of undefined is an uncontrolled one and React says so in the console. That
 * distinction must not reach the wire: an empty `regex` posted as '' is a pattern that matches
 * nothing, which is emphatically not what "no pattern" means.
 */
export function serializeRules(rules: RequestProfileRules) {
    return {
        subjectDnRules: rules.subjectDnRules.map((r) => ({
            field: r.field,
            requirement: r.requirement,
            fixedValue: r.fixedValue || undefined,
            regex: r.regex || undefined,
            maxLength: r.maxLength || undefined,
            defaultValue: r.defaultValue || undefined,
        })),
        sanRules: {
            allowedTypes: rules.sanRules.allowedTypes,
            required: rules.sanRules.required,
            // Only types that are actually permitted carry a rule. A leftover rule for a type the
            // profile no longer allows is dead weight that reads as policy on the next person to
            // open the JSON.
            rules: Object.fromEntries(
                Object.entries(rules.sanRules.rules)
                    .filter(([type]) => rules.sanRules.allowedTypes.includes(type))
                    .map(([type, rule]) => [type, { regex: rule.regex || undefined, maxCount: rule.maxCount }]),
            ),
        },
    };
}

/** The rules as "Copy as JSON" writes them: what the API stores, indented. */
export function rulesToJsonText(rules: RequestProfileRules): string {
    return JSON.stringify(serializeRules(rules), null, 2);
}

export type RulesImportResult =
    | { ok: true; rules: RequestProfileRules; summary: string[]; warnings: string[]; unchanged: boolean }
    | { ok: false; error: string };

const DN_RULE_KEYS = ['field', 'requirement', 'fixedValue', 'regex', 'maxLength', 'defaultValue'];
const SAN_RULES_KEYS = ['allowedTypes', 'required', 'rules'];
const SAN_TYPE_RULE_KEYS = ['regex', 'maxCount'];

const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isCount = (v: unknown) => typeof v === 'number' && Number.isInteger(v) && v >= 0;
const isSet = (v: unknown) => v !== undefined && v !== null;
const extraKeys = (o: Record<string, unknown>, known: string[]) => Object.keys(o).filter((k) => !known.includes(k));
/** The editor's spelling of a SAN type; the server matches SAN types ignoring case. */
const canonicalSanType = (t: string) => SAN_TYPE_OPTIONS.find((o) => o.toLowerCase() === t.toLowerCase()) ?? t;

/**
 * Checks pasted rules JSON against the rules model before "Paste JSON…" may apply it. Shapes
 * `parseRules` would quietly coerce (a misspelled requirement read as Optional, a field that is not
 * text read as CN) are errors here. A section left out keeps the current one.
 */
export function checkRulesImport(text: string, current: RequestProfileRules): RulesImportResult {
    if (!text.trim()) return { ok: false, error: 'Paste the rules JSON.' };
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch (err: any) { return { ok: false, error: `Not valid JSON: ${err?.message || 'parse error'}` }; }
    if (!isObject(parsed)) return { ok: false, error: 'Expected an object with subjectDnRules and sanRules.' };
    const hasDn = parsed.subjectDnRules !== undefined;
    const hasSan = parsed.sanRules !== undefined;
    if (!hasDn && !hasSan) return { ok: false, error: 'Neither subjectDnRules nor sanRules is present.' };

    const warnings: string[] = [];
    const ignored = extraKeys(parsed, ['subjectDnRules', 'sanRules']);
    if (ignored.length) warnings.push(`Only the rules are imported; ignored: ${ignored.join(', ')}.`);

    const dnSource: Record<string, unknown>[] = [];
    if (isSet(parsed.subjectDnRules)) {
        if (!Array.isArray(parsed.subjectDnRules)) return { ok: false, error: 'subjectDnRules must be an array.' };
        for (const [i, raw] of parsed.subjectDnRules.entries()) {
            const at = `subjectDnRules[${i}]`;
            if (!isObject(raw)) return { ok: false, error: `${at} must be an object.` };
            if (typeof raw.field !== 'string' || !raw.field.trim()) return { ok: false, error: `${at}.field must be a DN attribute such as CN.` };
            let requirement: string | undefined;
            if (isSet(raw.requirement)) {
                const given = String(raw.requirement).toLowerCase();
                requirement = typeof raw.requirement === 'string' ? REQUIREMENT_OPTIONS.find((r) => r.toLowerCase() === given) : undefined;
                if (!requirement) return { ok: false, error: `${at}.requirement must be one of ${REQUIREMENT_OPTIONS.join(', ')}.` };
            } else {
                warnings.push(`${at} (${raw.field}) has no requirement, so it is Optional.`);
            }
            for (const k of ['fixedValue', 'regex', 'defaultValue']) {
                if (isSet(raw[k]) && typeof raw[k] !== 'string') return { ok: false, error: `${at}.${k} must be text.` };
            }
            if (isSet(raw.maxLength) && !isCount(raw.maxLength)) return { ok: false, error: `${at}.maxLength must be a whole number.` };
            if (!DN_FIELD_OPTIONS.includes(raw.field)) warnings.push(`${at}: ${raw.field} is not a field this editor lists; it is kept.`);
            const extra = extraKeys(raw, DN_RULE_KEYS);
            if (extra.length) warnings.push(`${at}: ignored ${extra.join(', ')}.`);
            dnSource.push({ ...raw, requirement });
        }
    }
    if (hasDn && dnSource.length === 0) warnings.push('No subject DN rules: the editor starts one Required CN row, as for a new profile.');

    let sanSource: Record<string, unknown> | undefined;
    if (isSet(parsed.sanRules)) {
        const san = parsed.sanRules;
        if (!isObject(san)) return { ok: false, error: 'sanRules must be an object.' };
        if (isSet(san.allowedTypes)) {
            if (!Array.isArray(san.allowedTypes) || san.allowedTypes.some((t) => typeof t !== 'string')) {
                return { ok: false, error: 'sanRules.allowedTypes must be an array of type names.' };
            }
            const unknown = (san.allowedTypes as string[]).filter((t) => canonicalSanType(t) === t && !SAN_TYPE_OPTIONS.includes(t));
            if (unknown.length) warnings.push(`SAN types ${unknown.join(', ')} are not among ${SAN_TYPE_OPTIONS.join(', ')}; they are kept.`);
        } else {
            warnings.push('sanRules.allowedTypes is missing, so DNS and IP are allowed.');
        }
        if (isSet(san.required) && typeof san.required !== 'boolean') return { ok: false, error: 'sanRules.required must be true or false.' };
        if (isSet(san.rules)) {
            if (!isObject(san.rules)) return { ok: false, error: 'sanRules.rules must be an object keyed by SAN type.' };
            const allowed = (Array.isArray(san.allowedTypes) ? san.allowedTypes as string[] : ['DNS', 'IP']).map(canonicalSanType);
            for (const [type, rule] of Object.entries(san.rules)) {
                const at = `sanRules.rules.${type}`;
                if (!isObject(rule)) return { ok: false, error: `${at} must be an object.` };
                if (isSet(rule.regex) && typeof rule.regex !== 'string') return { ok: false, error: `${at}.regex must be text.` };
                if (isSet(rule.maxCount) && !isCount(rule.maxCount)) return { ok: false, error: `${at}.maxCount must be a whole number.` };
                if (!allowed.includes(canonicalSanType(type))) warnings.push(`${at} is for a type that is not allowed; it is dropped on save.`);
                const extra = extraKeys(rule, SAN_TYPE_RULE_KEYS);
                if (extra.length) warnings.push(`${at}: ignored ${extra.join(', ')}.`);
            }
        }
        const extra = extraKeys(san, SAN_RULES_KEYS);
        if (extra.length) warnings.push(`sanRules: ignored ${extra.join(', ')}.`);
        sanSource = {
            ...san,
            allowedTypes: Array.isArray(san.allowedTypes) ? (san.allowedTypes as string[]).map(canonicalSanType) : san.allowedTypes,
            rules: isObject(san.rules) ? Object.fromEntries(Object.entries(san.rules).map(([t, r]) => [canonicalSanType(t), r])) : san.rules,
        };
    } else if (hasSan) {
        warnings.push('sanRules is null, so DNS and IP are allowed.');
    }

    const read = parseRules({ subjectDnRules: dnSource, sanRules: sanSource });
    const rules: RequestProfileRules = {
        subjectDnRules: hasDn ? read.subjectDnRules : current.subjectDnRules,
        sanRules: hasSan ? read.sanRules : current.sanRules,
    };

    const summary: string[] = [hasDn
        ? `Subject DN rules: ${rules.subjectDnRules.length} (${rules.subjectDnRules.map((r) => `${r.field} ${r.requirement}`).join(', ')})`
        : 'Subject DN rules: not in the JSON; the current ones are kept'];
    if (hasSan) {
        const s = rules.sanRules;
        const perType = Object.entries(s.rules).filter(([t]) => s.allowedTypes.includes(t));
        summary.push(`SAN types allowed: ${s.allowedTypes.length ? s.allowedTypes.join(', ') : 'none'}`);
        summary.push(`SAN required: ${s.required ? 'Yes' : 'No'}`);
        summary.push(`Per-type SAN constraints: ${perType.length
            ? perType.map(([t, r]) => `${t} (${r.regex ? 'regex, ' : ''}max ${r.maxCount})`).join(', ')
            : 'none'}`);
    } else {
        summary.push('SAN rules: not in the JSON; the current ones are kept');
    }

    return { ok: true, rules, summary, warnings, unchanged: rulesToJsonText(rules) === rulesToJsonText(current) };
}
