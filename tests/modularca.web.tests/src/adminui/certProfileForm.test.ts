import { describe, expect, it } from 'vitest';
import type { CreateCertProfileRequest, UpdateCertProfileRequest } from '@shared/generated';
import {
    CT_LOGS_EMPTY_REASON, CT_LOGS_UNKNOWN_REASON, EXPIRY_ORDER_REASON, EXPIRY_PERCENT_REASON, EXPIRY_WINDOW_ORDER_REASON, EXPIRY_WINDOW_REASON,
    emptyForm, expiryAlertText, expiryProblems, expiryWarningText, formFromProfile, formToCreateBody, formToUpdateBody, isoWindowMs, validate,
} from '@adminui/pages/profiles/certProfile';
import { INHERITANCE_REASON, NAME_REQUIRED_REASON } from '@adminui/pages/profiles/profileFormCore';
import { bodyKeys, csv, dtoKeys, jsonList } from './profileFormKit';

/**
 * The certificate profile form model behind both /profiles/cert/new and /profiles/cert/:id. The
 * create and edit pages used to build their bodies separately; these pin that the one model emits
 * exactly the DTO, loses nothing on a load-and-save, and blocks Save for the same reasons in both
 * modes.
 */

const CREATE_KEYS = dtoKeys<CreateCertProfileRequest>({
    name: true, description: true, isCaProfile: true, keyUsages: true, extendedKeyUsages: true,
    validityPeriodMin: true, validityPeriodMax: true, allowedKeyAlgorithms: true, allowedKeySizes: true,
    allowedSignatureAlgorithms: true, certificateAuthorityId: true, inheritsFromId: true,
    inheritanceEnabled: true, allowWildcard: true, ctEnabled: true, ctLogIds: true,
    expiryWarningPercent: true, expiryWarningMaxWindow: true, expiryAlertPercent: true, expiryAlertMaxWindow: true,
    expiryNeverWarn: true, expiryWarningOverridesParent: true,
});
const UPDATE_KEYS = dtoKeys<UpdateCertProfileRequest>({
    name: true, description: true, isCaProfile: true, keyUsages: true, extendedKeyUsages: true,
    validityPeriodMin: true, validityPeriodMax: true, allowedKeyAlgorithms: true, allowedKeySizes: true,
    allowedSignatureAlgorithms: true, certificateAuthorityId: true, inheritsFromId: true,
    inheritanceEnabled: true, allowWildcard: true, ctEnabled: true, ctLogIds: true,
    expiryWarningPercent: true, expiryWarningMaxWindow: true, expiryAlertPercent: true, expiryAlertMaxWindow: true,
    expiryNeverWarn: true, expiryWarningOverridesParent: true,
});

/** A profile as GET /api/v1/admin/cert-profiles returns it, every settable field off its default. */
const stored = {
    id: '0b6f3f0e-1111-4c4c-9a9a-000000000001',
    name: 'TLS Server',
    description: 'Public web servers',
    isCaProfile: true,
    keyUsages: '["digitalSignature","keyEncipherment","keyCertSign"]',
    extendedKeyUsages: '["1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"]',
    extendedKeyUsageNames: ['Server Authentication', 'Client Authentication'],
    allowWildcard: true,
    ctEnabled: true,
    ctLogIds: '["0b6f3f0e-aaaa-4c4c-9a9a-00000000000a","0b6f3f0e-bbbb-4c4c-9a9a-00000000000b"]',
    validityPeriodMin: 'P1D',
    validityPeriodMax: 'P397D',
    allowedKeyAlgorithms: '["RSA","ECDSA"]',
    allowedKeySizes: '["2048","P-256"]',
    allowedSignatureAlgorithms: '["SHA256withRSA","SHA256withRSAandMGF1","SHA256withECDSA"]',
    certificateAuthorityId: '0b6f3f0e-2222-4c4c-9a9a-000000000002',
    inheritsFromId: '0b6f3f0e-3333-4c4c-9a9a-000000000003',
    inheritanceEnabled: true,
    expiryWarningPercent: 40,
    expiryWarningMaxWindow: 'P60D',
    expiryAlertPercent: 15,
    expiryAlertMaxWindow: 'P14D',
    expiryNeverWarn: true,
    expiryWarningOverridesParent: true,
};

describe('certificate profile form: shape', () => {
    it('posts exactly the CreateCertProfileRequest fields from an empty form', () => {
        const body = formToCreateBody(emptyForm());
        expect(bodyKeys(body)).toEqual(CREATE_KEYS);
        expect(body).toEqual({
            name: '', description: '', isCaProfile: false, keyUsages: '', extendedKeyUsages: '',
            validityPeriodMin: null, validityPeriodMax: null,
            allowedKeyAlgorithms: '[]', allowedKeySizes: '[]', allowedSignatureAlgorithms: '[]',
            certificateAuthorityId: null, inheritsFromId: null, inheritanceEnabled: false,
            allowWildcard: false, ctEnabled: false, ctLogIds: null,
            expiryWarningPercent: null, expiryWarningMaxWindow: null, expiryAlertPercent: null, expiryAlertMaxWindow: null,
            expiryNeverWarn: false, expiryWarningOverridesParent: false,
        });
    });

    it('puts exactly the UpdateCertProfileRequest fields', () => {
        expect(bodyKeys(formToUpdateBody(formFromProfile(stored)))).toEqual(UPDATE_KEYS);
    });

    it('creates and updates with the same body for the same form', () => {
        const form = formFromProfile(stored);
        expect(formToCreateBody(form)).toEqual(formToUpdateBody(form));
    });
});

describe('certificate profile form: round trip', () => {
    it('preserves every field of a stored profile through load and save', () => {
        const body = formToUpdateBody(formFromProfile(stored));
        expect(body.name).toBe(stored.name);
        expect(body.description).toBe(stored.description);
        expect(body.isCaProfile).toBe(true);
        expect(csv(body.keyUsages)).toEqual(jsonList(stored.keyUsages));
        expect(csv(body.extendedKeyUsages)).toEqual(jsonList(stored.extendedKeyUsages));
        expect(jsonList(body.allowedKeyAlgorithms)).toEqual(jsonList(stored.allowedKeyAlgorithms));
        expect(jsonList(body.allowedKeySizes)).toEqual(jsonList(stored.allowedKeySizes));
        expect(jsonList(body.allowedSignatureAlgorithms)).toEqual(jsonList(stored.allowedSignatureAlgorithms));
        expect(body.validityPeriodMin).toBe('P1D');
        expect(body.validityPeriodMax).toBe('P397D');
        expect(body.ctEnabled).toBe(true);
        expect(body.ctLogIds).toBe(stored.ctLogIds);
        expect(body.allowWildcard).toBe(true);
        expect(body.certificateAuthorityId).toBe(stored.certificateAuthorityId);
        expect(body.inheritsFromId).toBe(stored.inheritsFromId);
        expect(body.inheritanceEnabled).toBe(true);
        expect(body.expiryWarningPercent).toBe(40);
        expect(body.expiryWarningMaxWindow).toBe('P60D');
        expect(body.expiryAlertPercent).toBe(15);
        expect(body.expiryAlertMaxWindow).toBe('P14D');
        expect(body.expiryNeverWarn).toBe(true);
        expect(body.expiryWarningOverridesParent).toBe(true);
    });

    it('is stable: a saved body loads back into the same form', () => {
        const form = formFromProfile(stored);
        expect(formFromProfile(formToUpdateBody(form))).toEqual(form);
    });

    it('keeps a comma-separated ceiling instead of reading it as unrestricted', () => {
        // Written verbatim by policy sync; a JSON-only parse read it as [] and saved "unrestricted".
        const body = formToUpdateBody(formFromProfile({ ...stored, allowedKeyAlgorithms: 'RSA, ECDSA' }));
        expect(jsonList(body.allowedKeyAlgorithms)).toEqual(['RSA', 'ECDSA']);
    });

    it('canonicalises usage labels written by older builds', () => {
        const form = formFromProfile({ ...stored, keyUsages: 'Digital Signature, Key Encipherment', extendedKeyUsages: 'serverAuth' });
        expect(form.keyUsages).toEqual(['digitalSignature', 'keyEncipherment']);
        expect(form.extendedKeyUsages).toEqual(['1.3.6.1.5.5.7.3.1']);
    });

    it('opens a sparse row without inventing values', () => {
        expect(formFromProfile({ id: 'x', name: 'Bare' })).toEqual({ ...emptyForm(), name: 'Bare' });
    });
});

describe('certificate profile form: expiry warning', () => {
    const named = { ...emptyForm(), name: 'P' };

    it('saves blank percents and windows as null, so the parent value or the default applies', () => {
        const body = formToCreateBody({ ...named, expiryWarningPercent: ' ', expiryWarningMaxWindow: '' });
        expect(body.expiryWarningPercent).toBeNull();
        expect(body.expiryWarningMaxWindow).toBeNull();
        expect(formToCreateBody({ ...named, expiryAlertPercent: '5', expiryAlertMaxWindow: ' PT6H ' })).toMatchObject({ expiryAlertPercent: 5, expiryAlertMaxWindow: 'PT6H' });
    });

    it('loads stored percents as text', () => {
        expect(formFromProfile({ ...stored, expiryWarningPercent: 30, expiryAlertPercent: null })).toMatchObject({ expiryWarningPercent: '30', expiryAlertPercent: '' });
    });

    it('refuses what the server refuses', () => {
        expect(validate({ ...named, expiryWarningPercent: '0' }, 'create')).toEqual([EXPIRY_PERCENT_REASON]);
        expect(validate({ ...named, expiryAlertPercent: '101' }, 'create')).toEqual([EXPIRY_PERCENT_REASON]);
        expect(validate({ ...named, expiryWarningPercent: '12.5' }, 'create')).toEqual([EXPIRY_PERCENT_REASON]);
        expect(validate({ ...named, expiryWarningPercent: '10', expiryAlertPercent: '20' }, 'create')).toEqual([EXPIRY_ORDER_REASON]);
        expect(validate({ ...named, expiryWarningMaxWindow: '30 days' }, 'create')).toEqual([EXPIRY_WINDOW_REASON]);
        expect(validate({ ...named, expiryAlertMaxWindow: 'P0D' }, 'create')).toEqual([EXPIRY_WINDOW_REASON]);
        expect(validate({ ...named, expiryWarningMaxWindow: 'P7D', expiryAlertMaxWindow: 'P8D' }, 'create')).toEqual([EXPIRY_WINDOW_ORDER_REASON]);
        expect(validate({ ...named, expiryWarningPercent: '30', expiryAlertPercent: '30', expiryWarningMaxWindow: 'P30D', expiryAlertMaxWindow: 'PT6H' }, 'edit')).toEqual([]);
    });

    it('reads ISO 8601 windows', () => {
        expect(isoWindowMs('PT6H')).toBe(6 * 3_600_000);
        expect(isoWindowMs('P1W')).toBe(7 * 86_400_000);
        expect(isoWindowMs('P')).toBeNull();
        expect(isoWindowMs('PT')).toBeNull();
        expect(isoWindowMs('6h')).toBeNull();
    });

    it('measures months and years from now in UTC, as the server does', () => {
        const day = 86_400_000;
        const january = new Date(Date.UTC(2026, 0, 15, 12));
        const february = new Date(Date.UTC(2026, 1, 15, 12));
        expect(isoWindowMs('P1M', january)).toBe(31 * day);
        expect(isoWindowMs('P1M', february)).toBe(28 * day);
        expect(isoWindowMs('P1Y', february)).toBe(365 * day);
        expect(isoWindowMs('P1M1D', new Date(Date.UTC(2026, 0, 31)))).toBe(29 * day);
        expect(isoWindowMs('P1Y', new Date(Date.UTC(2028, 1, 29)))).toBe(365 * day);
        expect(isoWindowMs('P1MT1H', february)).toBe(28 * day + 3_600_000);
    });

    it('compares a month with 30 days by the month it is measured in, as the server refuses or accepts it', () => {
        const windows = { expiryWarningPercent: '', expiryAlertPercent: '', expiryWarningMaxWindow: 'P30D', expiryAlertMaxWindow: 'P1M' };
        expect(expiryProblems(windows, new Date(Date.UTC(2026, 0, 10)))).toEqual([EXPIRY_WINDOW_ORDER_REASON]);
        expect(expiryProblems(windows, new Date(Date.UTC(2026, 3, 10)))).toEqual([]);
        expect(expiryProblems(windows, new Date(Date.UTC(2026, 1, 10)))).toEqual([]);
    });

    it('describes the settings, with the CA default for a CA profile that sets none', () => {
        expect(expiryWarningText({})).toBe('30 % of lifetime left (default)');
        expect(expiryAlertText({ expiryAlertPercent: 5, expiryAlertMaxWindow: 'P7D' })).toBe('5 % of lifetime left, at most 7 days ahead');
        expect(expiryWarningText({ isCaProfile: true })).toBe('30 days before expiry (CA default)');
        expect(expiryAlertText({ isCaProfile: true })).toBe('7 days before expiry (CA default)');
        expect(expiryAlertText({ expiryNeverWarn: true })).toBe('Never: renewed automatically');
    });
});

describe('certificate profile form: validation', () => {
    it('blocks an unnamed profile in both modes', () => {
        expect(validate(emptyForm(), 'create')).toEqual([NAME_REQUIRED_REASON]);
        expect(validate(emptyForm(), 'edit')).toEqual([NAME_REQUIRED_REASON]);
    });

    it('blocks a parent without inheritance, and inheritance without a parent', () => {
        const named = { ...emptyForm(), name: 'P' };
        expect(validate({ ...named, inheritsFromId: 'parent' }, 'create')).toEqual([INHERITANCE_REASON]);
        expect(validate({ ...named, inheritanceEnabled: true }, 'edit')).toEqual([INHERITANCE_REASON]);
        expect(validate({ ...named, inheritsFromId: 'parent', inheritanceEnabled: true }, 'edit')).toEqual([]);
    });

    it('accepts a loaded profile as it stands', () => {
        expect(validate(formFromProfile(stored), 'edit')).toEqual([]);
    });
});

describe('certificate profile form: CT logs', () => {
    const LOG_A = '0b6f3f0e-aaaa-4c4c-9a9a-00000000000a';
    const LOG_B = '0b6f3f0e-bbbb-4c4c-9a9a-00000000000b';
    const catalog = [
        { id: LOG_A, name: 'Argon', url: 'https://ct.example/argon', enabled: true },
        { id: LOG_B, name: 'Xenon', url: 'https://ct.example/xenon', enabled: false },
    ];

    it('loads a stored list as Only these logs, and blank or null as Every enabled log', () => {
        expect(formFromProfile(stored)).toMatchObject({ ctLogIds: [LOG_A, LOG_B], ctLogsMode: 'only' });
        expect(formFromProfile({ ...stored, ctLogIds: null })).toMatchObject({ ctLogIds: [], ctLogsMode: 'any' });
        expect(formFromProfile({ ...stored, ctLogIds: '' })).toMatchObject({ ctLogIds: [], ctLogsMode: 'any' });
    });

    it('saves Every enabled log as null, so an inheriting profile takes its parent list', () => {
        const form = { ...formFromProfile(stored), ctLogsMode: 'any' as const };
        expect(formToUpdateBody(form).ctLogIds).toBeNull();
    });

    it('keeps a stored empty array as an empty array, which overrides a parent list', () => {
        const form = formFromProfile({ ...stored, ctLogIds: '[ ]' });
        expect(form.ctLogsMode).toBe('any');
        expect(formToUpdateBody(form).ctLogIds).toBe('[]');
    });

    it('saves ticked logs as a JSON array of ids', () => {
        const form = { ...formFromProfile({ ...stored, ctLogIds: null }), ctLogsMode: 'only' as const, ctLogIds: [LOG_B] };
        expect(formToUpdateBody(form).ctLogIds).toBe(JSON.stringify([LOG_B]));
    });

    it('blocks Only these logs with nothing ticked while CT is on', () => {
        const form = { ...formFromProfile(stored), ctLogsMode: 'only' as const, ctLogIds: [] };
        expect(validate(form, 'edit', catalog)).toEqual([CT_LOGS_EMPTY_REASON]);
        expect(validate({ ...form, ctEnabled: false }, 'edit', catalog)).toEqual([]);
    });

    it('blocks stored ids that name no log, once the catalog is known', () => {
        const form = formFromProfile({ ...stored, ctLogIds: `["${LOG_A}","not-a-log"]` });
        expect(validate(form, 'edit', catalog)).toEqual([CT_LOGS_UNKNOWN_REASON]);
        expect(validate(form, 'edit', null)).toEqual([]);
        expect(validate({ ...form, ctLogsMode: 'any' }, 'edit', catalog)).toEqual([]);
        expect(validate({ ...form, ctLogIds: [LOG_A] }, 'edit', catalog)).toEqual([]);
    });
});
