/*
 * The "Keys and signatures" editor model: a cert profile's AllowedKeyAlgorithms, AllowedKeySizes and
 * AllowedSignatureAlgorithms, edited as one set of key families. No React here, so
 * tests/modularca.web.tests can cover it.
 *
 * Server semantics this has to keep (IssuanceValidationService.ValidateAgainstCertProfile and
 * CsrService.IsValidKeyParameters):
 *   - an empty list is unrestricted (for an inheriting profile, ProfileResolutionService reads it as
 *     "take the parent's list");
 *   - algorithms and signatures compare case-insensitively, sizes exactly;
 *   - key sizes are one flat list shared by RSA and ECDSA, ignored for EdDSA and the PQC families
 *     (IsKeySizeIgnored).
 * The names below are what CertificateUtil.ParseCsr reports for a CSR.
 */

export type FamilyId = 'RSA' | 'ECDSA' | 'EdDSA' | 'ML-DSA' | 'SLH-DSA';

export interface KeyFamily {
    id: FamilyId;
    label: string;
    /** Algorithm names as the server spells them. */
    algorithms: readonly string[];
    /** Short labels for the algorithms of a multi-variant family. */
    variantLabels?: Readonly<Record<string, string>>;
    /** Key sizes or curves; empty when the server ignores size for the family. */
    sizes: readonly string[];
    sizeNoun?: 'Sizes' | 'Curves';
    /** Signature algorithms; for a fixed family each algorithm signs with its own name. */
    signatures: readonly string[];
    /** EdDSA and the PQC families: the signature algorithm IS the key algorithm. */
    fixedSignature: boolean;
    postQuantum?: boolean;
}

// The ...andMGF1 entries are RSASSA-PSS. They are NOT optional extras: CertPolicy
// .RsaSignaturePadding defaults to "PSS", so KeyAlgorithmPolicy signs RSA requests as
// SHA256withRSAandMGF1. A profile without it refuses every RSA key the server generates.
export const RSA_PSS_DEFAULT = 'SHA256withRSAandMGF1';

export const KEY_FAMILIES: readonly KeyFamily[] = [
    {
        id: 'RSA', label: 'RSA', algorithms: ['RSA'], fixedSignature: false,
        sizes: ['2048', '3072', '4096', '7680', '8192'], sizeNoun: 'Sizes',
        signatures: [
            'SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA',
            'SHA256withRSAandMGF1', 'SHA384withRSAandMGF1', 'SHA512withRSAandMGF1',
        ],
    },
    {
        id: 'ECDSA', label: 'ECDSA', algorithms: ['ECDSA'], fixedSignature: false,
        sizes: ['P-256', 'P-384', 'P-521'], sizeNoun: 'Curves',
        signatures: ['SHA256withECDSA', 'SHA384withECDSA', 'SHA512withECDSA'],
    },
    {
        id: 'EdDSA', label: 'EdDSA', algorithms: ['Ed25519', 'Ed448'], fixedSignature: true,
        sizes: [], signatures: ['Ed25519', 'Ed448'],
    },
    {
        id: 'ML-DSA', label: 'ML-DSA', algorithms: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'], fixedSignature: true,
        variantLabels: { 'ML-DSA-44': '44', 'ML-DSA-65': '65', 'ML-DSA-87': '87' },
        sizes: [], signatures: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'], postQuantum: true,
    },
    {
        id: 'SLH-DSA', label: 'SLH-DSA', algorithms: ['SLH-DSA-SHA2-128F'], fixedSignature: true,
        variantLabels: { 'SLH-DSA-SHA2-128F': 'SHA2-128F' },
        sizes: [], signatures: ['SLH-DSA-SHA2-128F'], postQuantum: true,
    },
];

export const ALL_ALGORITHMS: readonly string[] = KEY_FAMILIES.flatMap((f) => f.algorithms);
export const ALL_SIZES: readonly string[] = KEY_FAMILIES.flatMap((f) => f.sizes);
/**
 * Every signature algorithm offered, as a literal so SignatureAlgorithmVocabularyTests can hold it
 * to the bootstrap seed list. The web tests hold it to KEY_FAMILIES.
 */
export const ALLOWED_SIGNATURE_ALGORITHM_OPTIONS = [
    'SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA',
    'SHA256withRSAandMGF1', 'SHA384withRSAandMGF1', 'SHA512withRSAandMGF1',
    'SHA256withECDSA', 'SHA384withECDSA', 'SHA512withECDSA',
    'Ed25519', 'Ed448',
    'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F',
];
export const ALL_SIGNATURES: readonly string[] = ALLOWED_SIGNATURE_ALGORITHM_OPTIONS;

/** RSA signatures as a hash × padding grid. */
export const RSA_SIGNATURE_GRID: readonly { hash: string; pss: string; pkcs1: string }[] = [
    { hash: 'SHA-256', pss: 'SHA256withRSAandMGF1', pkcs1: 'SHA256withRSA' },
    { hash: 'SHA-384', pss: 'SHA384withRSAandMGF1', pkcs1: 'SHA384withRSA' },
    { hash: 'SHA-512', pss: 'SHA512withRSAandMGF1', pkcs1: 'SHA512withRSA' },
];

/** The hash KeyAlgorithmPolicy.ResolveSignatureAlgorithm pairs with each curve. */
export const ECDSA_CURVE_SIGNATURE: Readonly<Record<string, string>> = {
    'P-256': 'SHA256withECDSA', 'P-384': 'SHA384withECDSA', 'P-521': 'SHA512withECDSA',
};

export const familyById = (id: FamilyId): KeyFamily => KEY_FAMILIES.find((f) => f.id === id)!;
export const familyOfAlgorithm = (alg: string): KeyFamily | undefined => KEY_FAMILIES.find((f) => f.algorithms.includes(alg));

/** Sizes the server checks for a key of this algorithm. */
export const sizesFor = (alg: string): readonly string[] => familyOfAlgorithm(alg)?.sizes ?? [];
/** Signatures a key of this algorithm can carry. */
export const signaturesFor = (alg: string): readonly string[] => {
    const fam = familyOfAlgorithm(alg);
    if (!fam) return [];
    return fam.fixedSignature ? [alg] : fam.signatures;
};

/** Short label for a size, flagging the slow RSA sizes. */
export const sizeLabel = (size: string): string =>
    (size === '7680' || size === '8192') ? `${size} (high compute)` : size;

/** "SHA256withECDSA" → "SHA-256". */
export const hashLabel = (sig: string): string => {
    const m = /^SHA(\d{3})with/i.exec(sig);
    return m ? `SHA-${m[1]}` : sig;
};

export const variantLabel = (fam: KeyFamily, alg: string): string => fam.variantLabels?.[alg] ?? alg;

// ── State ─────────────────────────────────────────────────────────────────────

export interface KeyPolicyLists {
    algorithms: string[];
    sizes: string[];
    signatures: string[];
}
export type KeyPolicyDimension = keyof KeyPolicyLists;
export const DIMENSIONS: readonly KeyPolicyDimension[] = ['algorithms', 'sizes', 'signatures'];

export type KeyPolicyMode = 'any' | 'only';

export interface KeyPolicyState {
    mode: KeyPolicyMode;
    /** Ticked algorithms, in catalog order. */
    algorithms: string[];
    /** Selected sizes, in catalog order. */
    sizes: string[];
    /** Selected signatures, in catalog order. */
    signatures: string[];
    /**
     * Whether the stored list was non-empty. An empty one (unrestricted, or inherited) saves back as
     * empty while every option of the ticked families stays selected; an explicit one is never
     * widened to empty, because empty would also admit values outside this catalog.
     */
    explicit: Record<KeyPolicyDimension, boolean>;
    /** Stored values this catalog does not know. Kept verbatim on save. */
    extras: KeyPolicyLists;
    /** Known stored values that had no effect (a size or signature of an unticked family). Dropped on save. */
    dropped: { sizes: string[]; signatures: string[] };
    /** The lists as stored, so a save keeps their order and spelling. */
    stored: KeyPolicyLists;
}

const emptyLists = (): KeyPolicyLists => ({ algorithms: [], sizes: [], signatures: [] });

const ciLookup = (catalog: readonly string[]) => {
    const m = new Map<string, string>();
    for (const c of catalog) m.set(c.toLowerCase(), c);
    return (v: string): string | undefined => m.get(v.trim().toLowerCase());
};
const canonicalAlgorithm = ciLookup(ALL_ALGORITHMS);
const canonicalSignature = ciLookup(ALL_SIGNATURES);
// Sizes compare exactly on the server (List.Contains), so "p-256" is not P-256.
const canonicalSize = (v: string): string | undefined => (ALL_SIZES.includes(v.trim()) ? v.trim() : undefined);

const CANON: Record<KeyPolicyDimension, (v: string) => string | undefined> = {
    algorithms: canonicalAlgorithm, sizes: canonicalSize, signatures: canonicalSignature,
};
const CATALOG: Record<KeyPolicyDimension, readonly string[]> = {
    algorithms: ALL_ALGORITHMS, sizes: ALL_SIZES, signatures: ALL_SIGNATURES,
};

const inCatalogOrder = (dim: KeyPolicyDimension, values: Iterable<string>): string[] => {
    const set = new Set(values);
    return CATALOG[dim].filter((v) => set.has(v));
};
const uniq = (values: string[]): string[] => [...new Set(values)];

/** Sizes the ticked algorithms are checked against. */
export const liveSizes = (algorithms: readonly string[]): string[] =>
    inCatalogOrder('sizes', algorithms.flatMap((a) => sizesFor(a)));
/** Signatures the ticked algorithms can carry. */
export const liveSignatures = (algorithms: readonly string[]): string[] =>
    inCatalogOrder('signatures', algorithms.flatMap((a) => signaturesFor(a)));

const splitKnown = (dim: KeyPolicyDimension, raw: string[]) => {
    const known: string[] = [];
    const extras: string[] = [];
    for (const v of raw) {
        const c = CANON[dim](v);
        if (c) known.push(c);
        else if (v.trim() && !extras.includes(v)) extras.push(v);
    }
    return { known: uniq(known), extras };
};

/**
 * Reads the three stored lists into editor state.
 *
 * All three empty is "Any". Otherwise an empty dimension means every option of each ticked family
 * is selected, which `fromEditorState` turns back into an empty list while that stays true.
 */
export const toEditorState = (lists: Partial<KeyPolicyLists>): KeyPolicyState => {
    const raw: KeyPolicyLists = {
        algorithms: [...(lists.algorithms ?? [])],
        sizes: [...(lists.sizes ?? [])],
        signatures: [...(lists.signatures ?? [])],
    };
    if (DIMENSIONS.every((d) => raw[d].length === 0)) {
        return {
            mode: 'any', algorithms: [], sizes: [], signatures: [],
            explicit: { algorithms: false, sizes: false, signatures: false },
            extras: emptyLists(), dropped: { sizes: [], signatures: [] }, stored: emptyLists(),
        };
    }

    const algs = splitKnown('algorithms', raw.algorithms);
    const sizes = splitKnown('sizes', raw.sizes);
    const sigs = splitKnown('signatures', raw.signatures);

    const ticked = raw.algorithms.length > 0 ? inCatalogOrder('algorithms', algs.known) : [...ALL_ALGORITHMS];
    const liveS = liveSizes(ticked);
    const liveG = liveSignatures(ticked);

    return {
        mode: 'only',
        algorithms: ticked,
        sizes: raw.sizes.length > 0 ? liveS.filter((s) => sizes.known.includes(s)) : liveS,
        signatures: raw.signatures.length > 0 ? liveG.filter((s) => sigs.known.includes(s)) : liveG,
        explicit: {
            algorithms: raw.algorithms.length > 0,
            sizes: raw.sizes.length > 0,
            signatures: raw.signatures.length > 0,
        },
        extras: { algorithms: algs.extras, sizes: sizes.extras, signatures: sigs.extras },
        dropped: {
            sizes: inCatalogOrder('sizes', sizes.known.filter((s) => !liveS.includes(s))),
            signatures: inCatalogOrder('signatures', sigs.known.filter((s) => !liveG.includes(s))),
        },
        stored: raw,
    };
};

/** Stored entries still selected, in their stored order and spelling, then new ones in catalog order. */
const emit = (dim: KeyPolicyDimension, stored: string[], selected: string[], extras: string[]): string[] => {
    const want = new Set(selected);
    const keep = new Set(extras);
    const out: string[] = [];
    const seen = new Set<string>();
    for (const v of stored) {
        const c = CANON[dim](v);
        const key = c ?? `\u0000${v}`;
        if (seen.has(key)) continue;
        if ((c && want.has(c)) || (!c && keep.has(v))) { out.push(v); seen.add(key); }
    }
    for (const v of selected) if (!seen.has(v)) { out.push(v); seen.add(v); }
    for (const v of extras) if (!seen.has(`\u0000${v}`)) { out.push(v); seen.add(`\u0000${v}`); }
    return out;
};

const sameMembers = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((v) => b.includes(v));

/** The three lists to save. */
export const fromEditorState = (s: KeyPolicyState): KeyPolicyLists => {
    if (s.mode === 'any') return emptyLists();

    const algorithms = !s.explicit.algorithms && sameMembers(s.algorithms, ALL_ALGORITHMS) && s.extras.algorithms.length === 0
        ? []
        : emit('algorithms', s.stored.algorithms, s.algorithms, s.extras.algorithms);

    const dim = (d: 'sizes' | 'signatures', live: string[]) => {
        const selected = live.filter((v) => s[d].includes(v));
        if (!s.explicit[d] && sameMembers(selected, live) && s.extras[d].length === 0) return [];
        return emit(d, s.stored[d], selected, s.extras[d]);
    };
    return {
        algorithms,
        sizes: dim('sizes', liveSizes(s.algorithms)),
        signatures: dim('signatures', liveSignatures(s.algorithms)),
    };
};

// ── Parent ceiling ────────────────────────────────────────────────────────────

/** Whether the parent's effective list admits a value. No parent, or an empty list, admits all. */
export const parentAllows = (parent: KeyPolicyLists | null | undefined, dim: KeyPolicyDimension, value: string): boolean => {
    const list = parent?.[dim];
    if (!list || list.length === 0) return true;
    // ProfileResolutionService compares the subset case-insensitively for all three lists.
    return list.some((p) => p.trim().toLowerCase() === value.toLowerCase());
};

const clamp = (parent: KeyPolicyLists | null | undefined, dim: KeyPolicyDimension, values: string[]) =>
    values.filter((v) => parentAllows(parent, dim, v));

// ── Edits ─────────────────────────────────────────────────────────────────────

export const setMode = (s: KeyPolicyState, mode: KeyPolicyMode): KeyPolicyState => ({ ...s, mode });

/**
 * Ticks or unticks algorithms. Ticking adds every size and signature they can use (as far as the
 * parent allows); unticking removes them, so nothing is left behind to go stale.
 */
export const setAlgorithms = (s: KeyPolicyState, algs: readonly string[], on: boolean, parent?: KeyPolicyLists | null): KeyPolicyState => {
    const sizes = algs.flatMap((a) => sizesFor(a));
    const sigs = algs.flatMap((a) => signaturesFor(a));
    if (on) {
        const add = clamp(parent, 'algorithms', [...algs]);
        return {
            ...s,
            algorithms: inCatalogOrder('algorithms', [...s.algorithms, ...add]),
            sizes: inCatalogOrder('sizes', [...s.sizes, ...clamp(parent, 'sizes', sizes)]),
            signatures: inCatalogOrder('signatures', [...s.signatures, ...clamp(parent, 'signatures', sigs)]),
        };
    }
    return {
        ...s,
        algorithms: s.algorithms.filter((a) => !algs.includes(a)),
        sizes: s.sizes.filter((v) => !sizes.includes(v)),
        signatures: s.signatures.filter((v) => !sigs.includes(v)),
    };
};

export const setFamily = (s: KeyPolicyState, id: FamilyId, on: boolean, parent?: KeyPolicyLists | null): KeyPolicyState =>
    setAlgorithms(s, familyById(id).algorithms, on, parent);

const setValue = (s: KeyPolicyState, dim: 'sizes' | 'signatures', value: string, on: boolean, parent?: KeyPolicyLists | null): KeyPolicyState => {
    // Under a parent, the first edit of a dimension narrows it to what the parent allows, so the
    // explicit list it saves never names a value the parent would strip.
    const base = clamp(parent, dim, s[dim]);
    const next = on ? [...base, value] : base.filter((v) => v !== value);
    return { ...s, [dim]: inCatalogOrder(dim, clamp(parent, dim, next)) };
};
export const setSize = (s: KeyPolicyState, size: string, on: boolean, parent?: KeyPolicyLists | null) => setValue(s, 'sizes', size, on, parent);
export const setSignature = (s: KeyPolicyState, sig: string, on: boolean, parent?: KeyPolicyLists | null) => setValue(s, 'signatures', sig, on, parent);

export const removeExtra = (s: KeyPolicyState, dim: KeyPolicyDimension, value: string): KeyPolicyState =>
    ({ ...s, extras: { ...s.extras, [dim]: s.extras[dim].filter((v) => v !== value) } });

// ── Presets ───────────────────────────────────────────────────────────────────

export interface KeyPolicyPreset {
    id: 'modern' | 'broad' | 'pq-pilot';
    label: string;
    description: string;
    lists: KeyPolicyLists;
}

const RSA_ALL_SIGS = [...familyById('RSA').signatures];
const MODERN: KeyPolicyLists = {
    algorithms: ['RSA', 'ECDSA', 'Ed25519'],
    sizes: ['3072', '4096', 'P-256', 'P-384'],
    signatures: [...RSA_ALL_SIGS, 'SHA256withECDSA', 'SHA384withECDSA', 'Ed25519'],
};

export const PRESETS: readonly KeyPolicyPreset[] = [
    {
        id: 'modern', label: 'Modern',
        description: 'RSA 3072/4096 (PSS and PKCS#1, SHA-256 to SHA-512), ECDSA P-256/P-384 (SHA-256/384), Ed25519.',
        lists: MODERN,
    },
    {
        id: 'broad', label: 'Broad compatibility',
        description: 'Modern plus RSA 2048, P-521, ECDSA SHA-512 and Ed448.',
        lists: {
            algorithms: inCatalogOrder('algorithms', [...MODERN.algorithms, 'Ed448']),
            sizes: inCatalogOrder('sizes', [...MODERN.sizes, '2048', 'P-521']),
            signatures: inCatalogOrder('signatures', [...MODERN.signatures, 'SHA512withECDSA', 'Ed448']),
        },
    },
    {
        id: 'pq-pilot', label: 'Post-quantum pilot',
        description: 'Modern plus ML-DSA-44/65/87 and SLH-DSA-SHA2-128F.',
        lists: {
            algorithms: inCatalogOrder('algorithms', [...MODERN.algorithms, 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F']),
            sizes: [...MODERN.sizes],
            signatures: inCatalogOrder('signatures', [...MODERN.signatures, 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F']),
        },
    },
];

/** Fills the boxes from a preset; they stay editable. Values outside the catalog are kept. */
export const applyPreset = (s: KeyPolicyState, preset: KeyPolicyPreset, parent?: KeyPolicyLists | null): KeyPolicyState => ({
    ...s,
    mode: 'only',
    algorithms: inCatalogOrder('algorithms', clamp(parent, 'algorithms', preset.lists.algorithms)),
    sizes: inCatalogOrder('sizes', clamp(parent, 'sizes', preset.lists.sizes)),
    signatures: inCatalogOrder('signatures', clamp(parent, 'signatures', preset.lists.signatures)),
    explicit: { algorithms: true, sizes: true, signatures: true },
});

// ── Problems ──────────────────────────────────────────────────────────────────

export type KeyPolicyProblemCode =
    | 'nothing-ticked' | 'family-no-size' | 'family-no-signature' | 'server-signature'
    | 'dropped' | 'extras' | 'parent-disallowed';

export interface KeyPolicyProblem {
    code: KeyPolicyProblemCode;
    tone: 'crit' | 'warn' | 'info';
    /** Save stays disabled while a blocking problem stands. */
    blocking: boolean;
    message: string;
    /** The family the problem belongs to, so the editor can link it to that fieldset. */
    family?: FamilyId;
}

export interface ProblemOptions {
    parent?: KeyPolicyLists | null;
    /** 'algorithms' for a signing profile, which has no size or signature lists. */
    scope?: 'full' | 'algorithms';
}

const listText = (values: readonly string[]) => values.join(', ');

/** Every coherence problem in the state, worst first. */
export const problems = (s: KeyPolicyState, opts: ProblemOptions = {}): KeyPolicyProblem[] => {
    const { parent, scope = 'full' } = opts;
    const out: KeyPolicyProblem[] = [];
    if (s.mode === 'any') return out;

    if (s.algorithms.length === 0 && s.extras.algorithms.length === 0) {
        out.push({
            code: 'nothing-ticked', tone: 'crit', blocking: true,
            message: 'Only these is chosen but nothing is ticked. That would save as no restriction at all. Tick at least one family, or choose Any.',
        });
    }

    const lists = fromEditorState(s);

    if (scope === 'full') {
        const ticked = s.algorithms.filter((a) => parentAllows(parent, 'algorithms', a));

        for (const fam of KEY_FAMILIES) {
            const algs = ticked.filter((a) => fam.algorithms.includes(a));
            if (algs.length === 0) continue;

            if (fam.sizes.length > 0 && !fam.sizes.some((v) => s.sizes.includes(v) && parentAllows(parent, 'sizes', v))) {
                const flips = lists.sizes.length === 0;
                out.push({
                    code: 'family-no-size', family: fam.id, tone: flips ? 'crit' : 'warn', blocking: flips,
                    message: flips
                        ? `${fam.label} is ticked but no ${fam.sizeNoun === 'Curves' ? 'curve' : 'size'} is. With none ticked anywhere this would save as any size. Tick one, or untick ${fam.label}.`
                        : `${fam.label} is ticked but no ${fam.sizeNoun === 'Curves' ? 'curve' : 'size'} is, so every ${fam.label} key will be refused.`,
                });
            }

            const unsigned = algs.filter((a) => !signaturesFor(a).some((g) => s.signatures.includes(g) && parentAllows(parent, 'signatures', g)));
            if (unsigned.length > 0) {
                const flips = lists.signatures.length === 0;
                const who = fam.fixedSignature ? listText(unsigned) : fam.label;
                out.push({
                    code: 'family-no-signature', family: fam.id, tone: flips ? 'crit' : 'warn', blocking: flips,
                    message: flips
                        ? `${who} ${unsigned.length > 1 ? 'are' : 'is'} ticked but no signature for ${unsigned.length > 1 ? 'them' : 'it'} is. With none ticked anywhere this would save as any signature. Tick one, or untick ${who}.`
                        : `${who} ${unsigned.length > 1 ? 'are' : 'is'} ticked but no matching signature is, so every ${who} request will be refused.`,
                });
            }
        }

        // Keys the server generates itself are signed with a fixed pairing (KeyAlgorithmPolicy).
        if (lists.signatures.length > 0) {
            if (ticked.includes('RSA') && s.signatures.some((g) => familyById('RSA').signatures.includes(g)) && !s.signatures.includes(RSA_PSS_DEFAULT)) {
                out.push({
                    code: 'server-signature', family: 'RSA', tone: 'warn', blocking: false,
                    message: 'SHA-256 PSS is not ticked. The server signs the RSA requests it generates (CA, OCSP, TSA and server-side keys) as SHA-256 with PSS unless CertPolicy.RsaSignaturePadding is v15, so those requests will be refused.',
                });
            }
            if (ticked.includes('ECDSA')) {
                const missing = familyById('ECDSA').sizes
                    .filter((c) => s.sizes.includes(c) && parentAllows(parent, 'sizes', c) && !s.signatures.includes(ECDSA_CURVE_SIGNATURE[c]));
                const anyEcdsaSig = s.signatures.some((g) => familyById('ECDSA').signatures.includes(g));
                if (missing.length > 0 && anyEcdsaSig) {
                    out.push({
                        code: 'server-signature', family: 'ECDSA', tone: 'warn', blocking: false,
                        message: `The server signs keys it generates on ${missing.map((c) => `${c} with ${hashLabel(ECDSA_CURVE_SIGNATURE[c])}`).join(' and ')}, which ${missing.length > 1 ? 'are' : 'is'} not ticked, so those requests will be refused.`,
                    });
                }
            }
        }

        const deadSizes = s.dropped.sizes.filter((v) => !s.sizes.includes(v));
        const deadSigs = s.dropped.signatures.filter((v) => !s.signatures.includes(v));
        if (deadSizes.length + deadSigs.length > 0) {
            out.push({
                code: 'dropped', tone: 'warn', blocking: false,
                message: `Stored values that have no effect, because their family is not ticked, will be dropped on save: ${listText([...deadSizes, ...deadSigs])}.`,
            });
        }
    }

    const extras = scope === 'full' ? [...s.extras.algorithms, ...s.extras.sizes, ...s.extras.signatures] : s.extras.algorithms;
    if (extras.length > 0) {
        out.push({
            code: 'extras', tone: 'info', blocking: false,
            message: `Also stored, and kept as is because this editor does not offer ${extras.length > 1 ? 'them' : 'it'}: ${listText(extras)}.`,
        });
    }

    if (parent) {
        const dims: KeyPolicyDimension[] = scope === 'full' ? [...DIMENSIONS] : ['algorithms'];
        const outside = dims.flatMap((d) => lists[d].filter((v) => !parentAllows(parent, d, v)));
        if (outside.length > 0) {
            out.push({
                code: 'parent-disallowed', tone: 'warn', blocking: false,
                message: `Not allowed by the parent profile, so removed at issuance: ${listText(outside)}.`,
            });
        }
    }

    const rank = { crit: 0, warn: 1, info: 2 } as const;
    return out.sort((a, b) => rank[a.tone] - rank[b.tone]);
};

export const blockingProblems = (s: KeyPolicyState, opts: ProblemOptions = {}): KeyPolicyProblem[] =>
    problems(s, opts).filter((p) => p.blocking);

// ── Read-only summary ─────────────────────────────────────────────────────────

export interface KeyPolicyFamilyDescription {
    family: string;
    postQuantum: boolean;
    /** Ticked variants, for families with more than one (EdDSA, ML-DSA) or a labelled one. */
    variants: string[];
    /** Null when the family has no sizes or curves. */
    sizes: { noun: 'Sizes' | 'Curves'; values: string[] | 'any' } | null;
    /** Null when the signature follows from the key (EdDSA and the post-quantum families). */
    signatures: string[] | 'any' | null;
}

export interface KeyPolicyDescription {
    any: boolean;
    families: KeyPolicyFamilyDescription[];
    extras: string[];
}

const rsaSignatureValues = (s: KeyPolicyState): string[] =>
    RSA_SIGNATURE_GRID.flatMap((r) => {
        const modes = [s.signatures.includes(r.pss) ? 'PSS' : '', s.signatures.includes(r.pkcs1) ? 'PKCS#1' : ''].filter(Boolean);
        return modes.length ? [`${r.hash} (${modes.join(', ')})`] : [];
    });

/** The read-only view of a key policy: one entry per ticked family, each value listed on its own. */
export const describePolicy = (lists: Partial<KeyPolicyLists>, scope: 'full' | 'algorithms' = 'full'): KeyPolicyDescription => {
    const s = toEditorState(scope === 'full' ? lists : { algorithms: lists.algorithms ?? [] });
    if (s.mode === 'any') return { any: true, families: [], extras: [] };

    const families: KeyPolicyFamilyDescription[] = [];
    for (const fam of KEY_FAMILIES) {
        const algs = fam.algorithms.filter((a) => s.algorithms.includes(a));
        if (algs.length === 0) continue;
        const showVariants = fam.algorithms.length > 1 || !!fam.variantLabels;
        const full = scope === 'full' && !fam.fixedSignature;
        const sizeValues = fam.sizes.filter((v) => s.sizes.includes(v));
        const sigValues = fam.signatures.filter((v) => s.signatures.includes(v));
        families.push({
            family: fam.label,
            postQuantum: !!fam.postQuantum,
            variants: showVariants ? algs.map((a) => fam.variantLabels ? a : variantLabel(fam, a)) : [],
            sizes: full && fam.sizes.length > 0
                ? { noun: fam.sizeNoun ?? 'Sizes', values: !s.explicit.sizes && sizeValues.length === fam.sizes.length ? 'any' : sizeValues }
                : null,
            signatures: full
                ? (!s.explicit.signatures && sigValues.length === fam.signatures.length ? 'any' : fam.id === 'RSA' ? rsaSignatureValues(s) : sigValues.map(hashLabel))
                : null,
        });
    }
    const extras = scope === 'full' ? [...s.extras.algorithms, ...s.extras.sizes, ...s.extras.signatures] : s.extras.algorithms;
    return { any: false, families, extras };
};
