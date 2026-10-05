import { describe, expect, it } from 'vitest';
import {
    ALL_ALGORITHMS, ALL_SIGNATURES, ALL_SIZES, KEY_FAMILIES, PRESETS,
    type KeyPolicyLists, type KeyPolicyState,
    applyPreset, blockingProblems, fromEditorState, parentAllows, problems, removeExtra, setAlgorithms, setFamily,
    setMode, setSignature, setSize, toEditorState, describePolicy,
} from '@adminui/pages/profiles/keyPolicy';
import { emptyForm, formFromProfile, formToUpdateBody, validate, KEY_POLICY_REASON } from '@adminui/pages/profiles/certProfile';

/**
 * The "Keys and signatures" editor replaces three independent toggle lists. These pin that every
 * list the server can hold comes back out unchanged (or with only dead entries dropped), that the
 * presets are coherent, and that each coherence rule fires.
 */

const lists = (algorithms: string[], sizes: string[], signatures: string[]): KeyPolicyLists => ({ algorithms, sizes, signatures });
const roundTrip = (l: KeyPolicyLists) => fromEditorState(toEditorState(l));
const codes = (s: KeyPolicyState, parent?: KeyPolicyLists) => problems(s, { parent }).map((p) => p.code);

// BootstrapProfileSeeder.SeedInfrastructureCertProfiles, BootstrapModularCA, BootstrapService and
// SetupController's defaults all store exactly these.
const SEED_ALGORITHMS = ['RSA', 'ECDSA', 'Ed25519', 'Ed448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F'];
const SEED_SIZES = ['2048', '3072', '4096', '7680', '8192', 'P-256', 'P-384', 'P-521'];
const SEED_SIGNATURES = [
    'SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA', 'SHA256withRSAandMGF1', 'SHA384withRSAandMGF1', 'SHA512withRSAandMGF1',
    'SHA256withECDSA', 'SHA384withECDSA', 'SHA512withECDSA', 'Ed25519', 'Ed448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F',
];

describe('key policy catalog', () => {
    it('matches the server seed lists name for name and in order', () => {
        expect(ALL_ALGORITHMS).toEqual(SEED_ALGORITHMS);
        expect(ALL_SIZES).toEqual(SEED_SIZES);
        expect(ALL_SIGNATURES).toEqual(SEED_SIGNATURES);
    });

    it('offers exactly the signatures of its families', () => {
        expect(KEY_FAMILIES.flatMap((f) => f.signatures)).toEqual([...ALL_SIGNATURES]);
    });

    it('gives sizes only to the families the server checks them for', () => {
        expect(KEY_FAMILIES.filter((f) => f.sizes.length > 0).map((f) => f.id)).toEqual(['RSA', 'ECDSA']);
    });
});

describe('key policy: round trips', () => {
    const fixtures: [string, KeyPolicyLists][] = [
        ['all three empty (Any)', lists([], [], [])],
        ['the seeded full lists', lists(SEED_ALGORITHMS, SEED_SIZES, SEED_SIGNATURES)],
        ['CaCreationService signing AllowedAlgorithms as a cert ceiling', lists(SEED_ALGORITHMS, [], [])],
        ['restricted algorithms with unrestricted sizes and signatures', lists(['RSA', 'ECDSA'], [], [])],
        ['a mixed RSA and ECDSA size list', lists(['RSA', 'ECDSA'], ['2048', 'P-256'], ['SHA256withRSA', 'SHA256withRSAandMGF1', 'SHA256withECDSA'])],
        ['lists in click order, not catalog order', lists(['ECDSA', 'RSA'], ['P-384', '3072'], ['SHA384withECDSA', 'SHA256withRSAandMGF1'])],
        ['unrestricted algorithms with restricted sizes', lists([], ['2048', '3072'], [])],
        ['unrestricted algorithms with restricted signatures', lists([], [], ['SHA256withECDSA', 'Ed25519'])],
        ['EdDSA and PQC only, sizes ignored', lists(['Ed25519', 'ML-DSA-65'], [], ['Ed25519', 'ML-DSA-65'])],
        ['values this catalog does not know', lists(['RSA', 'DSA'], ['1024', '2048'], ['SHA1withRSA', 'SHA256withRSA'])],
        ['lower-case spellings', lists(['rsa'], ['2048'], ['sha256withrsa'])],
    ];
    for (const [name, l] of fixtures) {
        it(`returns ${name} unchanged`, () => {
            expect(roundTrip(l)).toEqual(l);
        });
    }

    it('reads all three empty as Any and anything else as Only these', () => {
        expect(toEditorState(lists([], [], [])).mode).toBe('any');
        expect(toEditorState(lists([], ['2048'], [])).mode).toBe('only');
    });

    it('ticks every family for an empty algorithm list and every option for an empty dimension', () => {
        const s = toEditorState(lists([], [], ['SHA256withRSA']));
        expect(s.algorithms).toEqual(SEED_ALGORITHMS);
        expect(s.sizes).toEqual(SEED_SIZES);
        expect(s.signatures).toEqual(['SHA256withRSA']);
    });

    it('drops sizes and signatures of unticked families, and says so', () => {
        const s = toEditorState(lists(['RSA'], ['2048', 'P-256'], ['SHA256withRSA', 'SHA256withECDSA']));
        expect(fromEditorState(s)).toEqual(lists(['RSA'], ['2048'], ['SHA256withRSA']));
        const dropped = problems(s).find((p) => p.code === 'dropped');
        expect(dropped?.message).toContain('P-256');
        expect(dropped?.message).toContain('SHA256withECDSA');
        expect(dropped?.blocking).toBe(false);
    });

    it('drops signatures when no ticked family can carry them', () => {
        const s = toEditorState(lists(['Ed25519'], ['4096'], ['Ed25519', 'SHA512withRSA']));
        expect(fromEditorState(s)).toEqual(lists(['Ed25519'], [], ['Ed25519']));
    });

    it('is stable once the dead entries are gone', () => {
        const once = roundTrip(lists(['RSA'], ['2048', 'P-256'], ['SHA256withRSA', 'SHA256withECDSA']));
        expect(roundTrip(once)).toEqual(once);
        expect(codes(toEditorState(once))).not.toContain('dropped');
    });

    it('keeps the cert profile body byte-compatible for a seeded profile', () => {
        const stored = {
            name: 'TSA Certificate Profile',
            allowedKeyAlgorithms: JSON.stringify(SEED_ALGORITHMS),
            allowedKeySizes: JSON.stringify(SEED_SIZES),
            allowedSignatureAlgorithms: JSON.stringify(SEED_SIGNATURES),
        };
        const body = formToUpdateBody(formFromProfile(stored));
        expect(body.allowedKeyAlgorithms).toBe(stored.allowedKeyAlgorithms);
        expect(body.allowedKeySizes).toBe(stored.allowedKeySizes);
        expect(body.allowedSignatureAlgorithms).toBe(stored.allowedSignatureAlgorithms);
    });
});

describe('key policy: edits', () => {
    it('ticking one family from Any restricts only the algorithm list', () => {
        let s = setMode(toEditorState({}), 'only');
        s = setFamily(s, 'RSA', true);
        expect(fromEditorState(s)).toEqual(lists(['RSA'], [], []));
    });

    it('unticking one size emits the explicit union of the ticked families', () => {
        let s = toEditorState(lists(['RSA', 'ECDSA'], [], []));
        s = setSize(s, 'P-521', false);
        expect(fromEditorState(s).sizes).toEqual(['2048', '3072', '4096', '7680', '8192', 'P-256', 'P-384']);
        s = setSize(s, 'P-521', true);
        expect(fromEditorState(s).sizes).toEqual([]);
    });

    it('never widens an explicit list to empty', () => {
        const s = toEditorState(lists(['RSA'], ['2048', '3072', '4096', '7680', '8192'], []));
        expect(fromEditorState(s).sizes).toEqual(['2048', '3072', '4096', '7680', '8192']);
    });

    it('unticking a family removes its sizes and signatures; ticking it again restores them all', () => {
        let s = toEditorState(lists(['RSA', 'ECDSA'], ['2048', 'P-256'], ['SHA256withRSA', 'SHA256withECDSA']));
        s = setFamily(s, 'ECDSA', false);
        expect(fromEditorState(s)).toEqual(lists(['RSA'], ['2048'], ['SHA256withRSA']));
        s = setFamily(s, 'ECDSA', true);
        expect(fromEditorState(s)).toEqual(lists(['RSA', 'ECDSA'], ['2048', 'P-256', 'P-384', 'P-521'],
            ['SHA256withRSA', 'SHA256withECDSA', 'SHA384withECDSA', 'SHA512withECDSA']));
    });

    it('ticks a fixed-signature variant together with its signature', () => {
        let s = toEditorState(lists(['RSA'], [], ['SHA256withRSAandMGF1']));
        s = setAlgorithms(s, ['Ed448'], true);
        expect(fromEditorState(s)).toEqual(lists(['RSA', 'Ed448'], [], ['SHA256withRSAandMGF1', 'Ed448']));
    });

    it('Any saves empty lists but remembers the ticks for Only these', () => {
        const restricted = toEditorState(lists(['RSA'], ['4096'], []));
        const any = setMode(restricted, 'any');
        expect(fromEditorState(any)).toEqual(lists([], [], []));
        expect(fromEditorState(setMode(any, 'only'))).toEqual(lists(['RSA'], ['4096'], []));
    });

    it('removes an unknown stored value on request', () => {
        const s = removeExtra(toEditorState(lists(['RSA', 'DSA'], [], [])), 'algorithms', 'DSA');
        expect(fromEditorState(s).algorithms).toEqual(['RSA']);
    });

    it('edits signatures without disturbing sizes', () => {
        const s = setSignature(toEditorState(lists(['RSA'], ['3072'], [])), 'SHA256withRSA', false);
        expect(fromEditorState(s)).toEqual(lists(['RSA'], ['3072'], ['SHA384withRSA', 'SHA512withRSA', 'SHA256withRSAandMGF1', 'SHA384withRSAandMGF1', 'SHA512withRSAandMGF1']));
    });
});

describe('key policy: presets', () => {
    for (const preset of PRESETS) {
        it(`${preset.label} names only catalog values and is coherent`, () => {
            for (const a of preset.lists.algorithms) expect(ALL_ALGORITHMS).toContain(a);
            for (const v of preset.lists.sizes) expect(ALL_SIZES).toContain(v);
            for (const g of preset.lists.signatures) expect(ALL_SIGNATURES).toContain(g);
            const s = applyPreset(setMode(toEditorState({}), 'only'), preset);
            expect(fromEditorState(s)).toEqual(preset.lists);
            expect(problems(s)).toEqual([]);
            expect(roundTrip(preset.lists)).toEqual(preset.lists);
        });
    }

    it('Modern, Broad compatibility and Post-quantum pilot hold what the owner asked for', () => {
        const [modern, broad, pq] = PRESETS;
        expect(modern.lists).toEqual(lists(
            ['RSA', 'ECDSA', 'Ed25519'], ['3072', '4096', 'P-256', 'P-384'],
            ['SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA', 'SHA256withRSAandMGF1', 'SHA384withRSAandMGF1', 'SHA512withRSAandMGF1', 'SHA256withECDSA', 'SHA384withECDSA', 'Ed25519'],
        ));
        expect(broad.lists.algorithms).toEqual(['RSA', 'ECDSA', 'Ed25519', 'Ed448']);
        expect(broad.lists.sizes).toEqual(['2048', '3072', '4096', 'P-256', 'P-384', 'P-521']);
        expect(broad.lists.signatures).toEqual(expect.arrayContaining(['SHA512withECDSA', 'Ed448']));
        expect(pq.lists.algorithms).toEqual(['RSA', 'ECDSA', 'Ed25519', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F']);
        expect(pq.lists.signatures).toEqual(expect.arrayContaining(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F']));
    });

    it('keeps a preset inside the parent ceiling', () => {
        const parent = lists(['RSA', 'ECDSA'], ['3072', 'P-256'], []);
        const s = applyPreset(setMode(toEditorState({}), 'only'), PRESETS[0], parent);
        expect(fromEditorState(s).algorithms).toEqual(['RSA', 'ECDSA']);
        expect(fromEditorState(s).sizes).toEqual(['3072', 'P-256']);
    });
});

describe('key policy: problems', () => {
    it('blocks Only these with nothing ticked', () => {
        const s = setMode(toEditorState({}), 'only');
        expect(codes(s)).toEqual(['nothing-ticked']);
        expect(blockingProblems(s)).toHaveLength(1);
        expect(fromEditorState(s)).toEqual(lists([], [], []));
    });

    it('warns about a ticked family with no size when other sizes remain', () => {
        const s = toEditorState(lists(['RSA', 'ECDSA'], ['2048'], []));
        const p = problems(s).find((x) => x.code === 'family-no-size');
        expect(p).toMatchObject({ family: 'ECDSA', tone: 'warn', blocking: false });
    });

    it('blocks a ticked family with no size when that would save as any size', () => {
        let s = toEditorState(lists(['RSA'], ['2048'], []));
        s = setSize(s, '2048', false);
        expect(fromEditorState(s).sizes).toEqual([]);
        expect(problems(s).find((x) => x.code === 'family-no-size')).toMatchObject({ tone: 'crit', blocking: true });
    });

    it('warns about a ticked family that would accept no signature', () => {
        const s = toEditorState(lists(['RSA', 'ECDSA'], [], ['SHA256withRSAandMGF1']));
        expect(problems(s).find((x) => x.code === 'family-no-signature')).toMatchObject({ family: 'ECDSA', tone: 'warn', blocking: false });
    });

    it('blocks when no ticked family keeps a signature', () => {
        let s = toEditorState(lists(['ECDSA'], [], ['SHA256withECDSA']));
        s = setSignature(s, 'SHA256withECDSA', false);
        expect(problems(s).find((x) => x.code === 'family-no-signature')).toMatchObject({ tone: 'crit', blocking: true });
    });

    it('names a fixed-signature variant whose signature is missing', () => {
        const s = toEditorState(lists(['Ed25519', 'Ed448'], [], ['Ed25519']));
        expect(problems(s).find((x) => x.code === 'family-no-signature')?.message).toContain('Ed448');
    });

    it('warns when RSA lacks the server-default SHA-256 PSS signature', () => {
        const s = toEditorState(lists(['RSA'], [], ['SHA256withRSA']));
        expect(problems(s).find((x) => x.code === 'server-signature')).toMatchObject({ family: 'RSA', tone: 'warn' });
    });

    it('warns when a ticked curve lacks the hash the server pairs with it', () => {
        const s = toEditorState(lists(['ECDSA'], ['P-256', 'P-384'], ['SHA256withECDSA']));
        expect(problems(s).find((x) => x.code === 'server-signature')?.message).toContain('P-384');
    });

    it('reports unknown stored values as kept', () => {
        const s = toEditorState(lists(['RSA', 'DSA'], [], []));
        expect(problems(s).find((x) => x.code === 'extras')).toMatchObject({ tone: 'info', blocking: false });
    });

    it('flags explicit values the parent does not allow', () => {
        const s = toEditorState(lists(['RSA', 'ECDSA'], [], []));
        expect(codes(s, lists(['RSA'], [], []))).toContain('parent-disallowed');
        expect(codes(s, lists([], [], []))).not.toContain('parent-disallowed');
    });

    it('reports nothing for Any', () => {
        expect(problems(toEditorState({}))).toEqual([]);
    });

    it('blocks the cert profile form on a blocking problem only', () => {
        const named = { ...emptyForm(), name: 'P' };
        expect(validate({ ...named, keyPolicy: setMode(named.keyPolicy, 'only') }, 'create')).toEqual([KEY_POLICY_REASON]);
        expect(validate({ ...named, keyPolicy: toEditorState(lists(['RSA', 'ECDSA'], ['2048'], [])) }, 'edit')).toEqual([]);
    });
});

describe('key policy: parent ceiling', () => {
    it('treats an empty parent list as allowing everything, and compares case-insensitively', () => {
        expect(parentAllows(null, 'algorithms', 'RSA')).toBe(true);
        expect(parentAllows(lists([], [], []), 'sizes', '2048')).toBe(true);
        expect(parentAllows(lists(['rsa'], [], []), 'algorithms', 'RSA')).toBe(true);
        expect(parentAllows(lists(['RSA'], [], []), 'algorithms', 'ECDSA')).toBe(false);
    });

    it('does not tick a family the parent refuses', () => {
        const s = setFamily(setMode(toEditorState({}), 'only'), 'ECDSA', true, lists(['RSA'], [], []));
        expect(s.algorithms).toEqual([]);
    });

    it('keeps an untouched inherited dimension empty, and narrows it to the parent on the first edit', () => {
        const parent = lists([], ['3072', '4096'], []);
        const s = toEditorState(lists(['RSA'], [], []));
        expect(fromEditorState(s).sizes).toEqual([]);
        const edited = setSize(s, '4096', false, parent);
        expect(fromEditorState(edited).sizes).toEqual(['3072']);
    });
});

describe('key policy: read-only description', () => {
    it('lists each family with its own rows and one value per entry', () => {
        const d = describePolicy(lists(['RSA', 'ECDSA', 'Ed25519'], ['3072', '4096', 'P-256', 'P-384'],
            ['SHA256withRSA', 'SHA256withRSAandMGF1', 'SHA384withRSAandMGF1', 'SHA256withECDSA', 'SHA384withECDSA', 'Ed25519']));
        expect(d.families).toEqual([
            { family: 'RSA', postQuantum: false, variants: [], sizes: { noun: 'Sizes', values: ['3072', '4096'] }, signatures: ['SHA-256 (PSS, PKCS#1)', 'SHA-384 (PSS)'] },
            { family: 'ECDSA', postQuantum: false, variants: [], sizes: { noun: 'Curves', values: ['P-256', 'P-384'] }, signatures: ['SHA-256', 'SHA-384'] },
            { family: 'EdDSA', postQuantum: false, variants: ['Ed25519'], sizes: null, signatures: null },
        ]);
    });

    it('says any for a dimension left empty, and names post-quantum variants in full', () => {
        const d = describePolicy(lists(['RSA', 'ML-DSA-65'], [], []));
        expect(d.families[0].sizes).toEqual({ noun: 'Sizes', values: 'any' });
        expect(d.families[0].signatures).toBe('any');
        expect(d.families[1]).toMatchObject({ family: 'ML-DSA', postQuantum: true, variants: ['ML-DSA-65'], sizes: null, signatures: null });
    });

    it('lists families only for a signing profile', () => {
        const d = describePolicy({ algorithms: ['RSA', 'Ed448'] }, 'algorithms');
        expect(d.families.map((f) => [f.family, f.variants, f.sizes, f.signatures])).toEqual([['RSA', [], null, null], ['EdDSA', ['Ed448'], null, null]]);
        expect(describePolicy({ algorithms: [] }, 'algorithms').any).toBe(true);
    });
});
