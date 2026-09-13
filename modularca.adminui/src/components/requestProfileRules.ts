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
