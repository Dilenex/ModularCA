import { describe, expect, it } from 'vitest';
import {
    DEFAULT_SAN_MAX_COUNT, checkRulesImport, emptyRules, parseRules, rulesToJsonText, serializeRules,
} from '@adminui/components/requestProfileRules';

/**
 * The conversions behind the request-profile rules editor.
 *
 * Editing an existing request profile used to be two textareas of raw JSON, while creating one
 * next to it had a structured form — so these functions are what let one editor serve both. Two
 * things about that make them worth covering rather than trusting.
 *
 * The first is that every profile in an existing installation was authored through that textarea,
 * which validated nothing beyond `JSON.parse`. Whatever is in those rows is what `parseRules` has
 * to open, and a structured editor that throws on a malformed rule would lock an operator out of
 * exactly the profile they need to repair.
 *
 * The second is the empty-string convention. A controlled React input cannot hold `undefined`
 * without React objecting, so unset optional fields are '' in the editor — and '' must not reach
 * the API, where an empty `regex` is a pattern matching nothing rather than the absence of a
 * pattern. `serializeRules` is the only thing standing between those two facts.
 */
describe('parseRules', () => {
    it('reads a well-formed profile unchanged', () => {
        const parsed = parseRules({
            subjectDnRules: [{ field: 'CN', requirement: 'Required', regex: '^[a-z]+$', maxLength: 64 }],
            sanRules: { allowedTypes: ['DNS'], required: true, rules: { DNS: { regex: '\\.example\\.com$', maxCount: 5 } } },
        });

        expect(parsed.subjectDnRules).toHaveLength(1);
        expect(parsed.subjectDnRules[0]).toMatchObject({ field: 'CN', requirement: 'Required', maxLength: 64 });
        expect(parsed.sanRules.required).toBe(true);
        expect(parsed.sanRules.rules.DNS).toEqual({ regex: '\\.example\\.com$', maxCount: 5 });
    });

    it('opens a profile whose rules are null', () => {
        // The JSON textarea accepted this happily for as long as it shipped.
        const parsed = parseRules({ subjectDnRules: null, sanRules: null });
        expect(parsed.subjectDnRules).toHaveLength(1);
        expect(parsed.sanRules.allowedTypes).toEqual(['DNS', 'IP']);
    });

    it('opens a profile with no rules at all', () => {
        expect(parseRules({}).subjectDnRules).toHaveLength(1);
        expect(parseRules(null).subjectDnRules).toHaveLength(1);
        expect(parseRules(undefined).sanRules.rules).toEqual({});
    });

    it('substitutes a usable value for a rule missing its requirement', () => {
        // Optional, not Required: inventing a constraint the stored profile never expressed would
        // silently start rejecting enrollments that used to succeed.
        const parsed = parseRules({ subjectDnRules: [{ field: 'OU' }] });
        expect(parsed.subjectDnRules[0].requirement).toBe('Optional');
    });

    it('replaces a requirement outside the vocabulary rather than showing a blank dropdown', () => {
        const parsed = parseRules({ subjectDnRules: [{ field: 'CN', requirement: 'Mandatory' }] });
        expect(parsed.subjectDnRules[0].requirement).toBe('Optional');
    });

    it('discards non-string SAN types instead of rendering them as toggles', () => {
        const parsed = parseRules({ sanRules: { allowedTypes: ['DNS', 42, null, 'IP'] } });
        expect(parsed.sanRules.allowedTypes).toEqual(['DNS', 'IP']);
    });

    it('defaults a per-type rule that omits maxCount to the server default', () => {
        const parsed = parseRules({ sanRules: { allowedTypes: ['DNS'], rules: { DNS: { regex: 'x' } } } });
        expect(parsed.sanRules.rules.DNS.maxCount).toBe(DEFAULT_SAN_MAX_COUNT);
    });

    it('always yields at least one DN row', () => {
        // An empty table offers nothing to click and reads as a broken page rather than an empty one.
        expect(parseRules({ subjectDnRules: [] }).subjectDnRules).toHaveLength(1);
    });
});

describe('serializeRules', () => {
    it('drops empty strings rather than sending them as constraints', () => {
        const body = serializeRules(emptyRules());
        const rule = body.subjectDnRules[0];

        // An empty regex is a pattern that matches nothing — the opposite of "no pattern".
        expect(rule.regex).toBeUndefined();
        expect(rule.fixedValue).toBeUndefined();
        expect(rule.defaultValue).toBeUndefined();
        expect(rule.maxLength).toBeUndefined();
        expect(rule.field).toBe('CN');
    });

    it('keeps values that were actually set', () => {
        const rules = parseRules({
            subjectDnRules: [{ field: 'CN', requirement: 'Required', regex: '^host-', maxLength: 32, defaultValue: 'host-1' }],
        });
        const rule = serializeRules(rules).subjectDnRules[0];

        expect(rule).toMatchObject({ regex: '^host-', maxLength: 32, defaultValue: 'host-1' });
    });

    it('carries per-type SAN rules through', () => {
        // The regression this whole editor exists to fix: the create form posted `rules: {}`
        // unconditionally, so a per-type regex or maxCount could not be created there at all.
        const rules = parseRules({
            sanRules: { allowedTypes: ['DNS'], required: false, rules: { DNS: { regex: '\\.corp$', maxCount: 3 } } },
        });

        expect(serializeRules(rules).sanRules.rules).toEqual({ DNS: { regex: '\\.corp$', maxCount: 3 } });
    });

    it('drops a per-type rule for a type the profile no longer allows', () => {
        // Toggling a type off then saving must not leave policy behind for a type that is never
        // consulted — it reads as an active constraint to the next person who opens the JSON.
        const rules = parseRules({
            sanRules: { allowedTypes: ['DNS', 'IP'], rules: { DNS: { maxCount: 3 }, IP: { maxCount: 1 } } },
        });
        rules.sanRules.allowedTypes = ['DNS'];

        expect(Object.keys(serializeRules(rules).sanRules.rules)).toEqual(['DNS']);
    });

    it('round-trips a profile without altering it', () => {
        // Opening a profile and saving it with no edits must produce what was already stored.
        const stored = {
            subjectDnRules: [
                { field: 'CN', requirement: 'Required', regex: '^[a-z0-9.-]+$', maxLength: 64 },
                { field: 'O', requirement: 'Optional', fixedValue: 'Example Corp' },
            ],
            sanRules: { allowedTypes: ['DNS', 'IP'], required: true, rules: { DNS: { regex: '\\.example\\.com$', maxCount: 10 } } },
        };

        const once = serializeRules(parseRules(stored));
        const twice = serializeRules(parseRules(once));

        expect(twice).toEqual(once);
        expect(once.subjectDnRules[1]).toMatchObject({ field: 'O', fixedValue: 'Example Corp' });
        expect(once.sanRules).toMatchObject({ allowedTypes: ['DNS', 'IP'], required: true });
    });
});

describe('rules JSON import and export', () => {
    const stored = {
        subjectDnRules: [
            { field: 'CN', requirement: 'Required', regex: '^[a-z]+$', maxLength: 64 },
            { field: 'O', requirement: 'Optional', fixedValue: 'Acme' },
        ],
        sanRules: { allowedTypes: ['DNS', 'IP'], required: true, rules: { DNS: { regex: '\\.example\\.com$', maxCount: 5 } } },
    };
    const err = (text: string) => {
        const r = checkRulesImport(text, emptyRules());
        if (r.ok) throw new Error('expected an error');
        return r.error;
    };

    it('exports what the API stores, indented, and imports it back unchanged', () => {
        const rules = parseRules(stored);
        const text = rulesToJsonText(rules);
        expect(JSON.parse(text)).toEqual(serializeRules(rules));
        expect(text).toContain('\n  "subjectDnRules": [');
        const back = checkRulesImport(text, rules);
        expect(back.ok).toBe(true);
        if (!back.ok) return;
        expect(back.rules).toEqual(rules);
        expect(back.unchanged).toBe(true);
        expect(back.warnings).toEqual([]);
    });

    it('previews counts and types', () => {
        const r = checkRulesImport(JSON.stringify(stored), emptyRules());
        expect(r.ok).toBe(true);
        if (!r.ok) return;
        expect(r.unchanged).toBe(false);
        expect(r.summary).toEqual([
            'Subject DN rules: 2 (CN Required, O Optional)',
            'SAN types allowed: DNS, IP',
            'SAN required: Yes',
            'Per-type SAN constraints: DNS (regex, max 5)',
        ]);
    });

    it('refuses text that is not JSON, or not the rules shape', () => {
        expect(err('')).toBe('Paste the rules JSON.');
        expect(err('{ subjectDnRules: [] }')).toMatch(/^Not valid JSON/);
        expect(err('[1, 2]')).toMatch(/Expected an object/);
        expect(err('{"name": "x"}')).toMatch(/Neither subjectDnRules nor sanRules/);
        expect(err('{"subjectDnRules": {}}')).toBe('subjectDnRules must be an array.');
        expect(err('{"subjectDnRules": ["CN"]}')).toBe('subjectDnRules[0] must be an object.');
        expect(err('{"subjectDnRules": [{"requirement": "Required"}]}')).toMatch(/field must be a DN attribute/);
        expect(err('{"subjectDnRules": [{"field": "CN", "maxLength": "64"}]}')).toMatch(/maxLength must be a whole number/);
        expect(err('{"sanRules": {"allowedTypes": "DNS"}}')).toMatch(/allowedTypes must be an array/);
        expect(err('{"sanRules": {"required": "yes"}}')).toMatch(/required must be true or false/);
        expect(err('{"sanRules": {"rules": {"DNS": {"maxCount": -1}}}}')).toMatch(/maxCount must be a whole number/);
    });

    it('refuses a requirement parseRules would quietly read as Optional, and accepts any case', () => {
        expect(err('{"subjectDnRules": [{"field": "CN", "requirement": "Mandatory"}]}')).toMatch(/requirement must be one of/);
        const r = checkRulesImport('{"subjectDnRules": [{"field": "CN", "requirement": "required"}]}', emptyRules());
        expect(r.ok && r.rules.subjectDnRules[0].requirement).toBe('Required');
    });

    it('keeps a section the JSON leaves out', () => {
        const current = parseRules(stored);
        const r = checkRulesImport('{"sanRules": {"allowedTypes": ["Email"], "required": false}}', current);
        expect(r.ok).toBe(true);
        if (!r.ok) return;
        expect(r.rules.subjectDnRules).toEqual(current.subjectDnRules);
        expect(r.rules.sanRules.allowedTypes).toEqual(['Email']);
        expect(r.summary[0]).toMatch(/current ones are kept/);
    });

    it('warns about what is ignored, coerced or dropped', () => {
        const r = checkRulesImport(JSON.stringify({
            name: 'Whole profile pasted',
            subjectDnRules: [{ field: 'serialNumber', extra: 1 }],
            sanRules: { allowedTypes: ['dns', 'X400'], rules: { IP: { maxCount: 2 } } },
        }), emptyRules());
        expect(r.ok).toBe(true);
        if (!r.ok) return;
        expect(r.warnings).toEqual([
            'Only the rules are imported; ignored: name.',
            'subjectDnRules[0] (serialNumber) has no requirement, so it is Optional.',
            'subjectDnRules[0]: serialNumber is not a field this editor lists; it is kept.',
            'subjectDnRules[0]: ignored extra.',
            'SAN types X400 are not among DNS, IP, Email, URI, UPN; they are kept.',
            'sanRules.rules.IP is for a type that is not allowed; it is dropped on save.',
        ]);
        expect(r.rules.subjectDnRules[0]).toMatchObject({ field: 'serialNumber', requirement: 'Optional' });
    });

    it('spells SAN types as the editor does, since the server matches them ignoring case', () => {
        const r = checkRulesImport('{"sanRules": {"allowedTypes": ["dns", "email"], "rules": {"Dns": {"maxCount": 3}}}}', emptyRules());
        expect(r.ok).toBe(true);
        if (!r.ok) return;
        expect(r.rules.sanRules.allowedTypes).toEqual(['DNS', 'Email']);
        expect(r.rules.sanRules.rules).toEqual({ DNS: { regex: '', maxCount: 3 } });
        expect(r.warnings).toEqual([]);
    });
});
