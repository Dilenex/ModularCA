import { useEffect, useState } from 'react';
import { apiGet } from '../api/client';
import {
    DEFAULT_EKU_OPTIONS, DEFAULT_EKU_LABELS, DEFAULT_EKU_ALIASES,
    KEY_USAGE_OPTIONS, keyUsageLabel,
} from '../pages/profileHelpers';
import { canonicalizeUsage } from '@shared/generated/usageVocabulary';

/**
 * The extended-key-usage vocabulary the server will actually accept, read from the OID catalog.
 *
 * The profile pages used to carry a hardcoded list of six OIDs. That was already wrong — it never
 * offered Smart Card Logon, which the catalog has held all along and the server has always
 * permitted, so a smart-card profile could not be built in the UI at all. Now that the catalog is
 * extensible it is worse than wrong, it is destructive: `canonicalizeUsages` DROPS any stored
 * value that matches no option and the result is written straight back on save, so opening a
 * profile that uses a catalog entry the UI has never heard of and pressing Save would silently
 * strip that usage from the profile.
 *
 * The built-in defaults remain as a fallback so the pages render correctly before the fetch
 * resolves and if it fails — a transient error must not turn into a blank picker that quietly
 * erases a selection.
 */
export interface OidCatalogEntry {
    oid: string;
    friendlyName: string;
    keyUsage: string;
    isDefaultEntry: boolean;
}

export interface EkuCatalog {
    /** Canonical option values (OIDs), for pickers and for `canonicalizeUsages`. */
    options: string[];
    /** Friendly name → OID, so a profile that stored the name still resolves. */
    aliases: Record<string, string>;
    /** Presentation only — never persist the result. */
    label: (oid: string) => string;
    /** False until the catalog has been fetched at least once this session. */
    loaded: boolean;
    /** Options offered here that the server's catalog lacks. See {@link UsageCatalog}. */
    missingFromCatalog: string[];
}

// One fetch per session, shared by every page that needs the vocabulary.
let cache: OidCatalogEntry[] | null = null;
let inflight: Promise<OidCatalogEntry[]> | null = null;

function loadCatalog(): Promise<OidCatalogEntry[]> {
    if (cache) return Promise.resolve(cache);
    if (!inflight) {
        inflight = apiGet<OidCatalogEntry[]>('/api/v1/admin/oid-options')
            .then((rows) => { cache = rows || []; return cache; })
            .catch(() => {
                // Fall back to the built-ins rather than an empty vocabulary. Caching the empty
                // result would make one failed request poison the rest of the session.
                inflight = null;
                return [];
            });
    }
    return inflight;
}

/** Humanises a camelCase catalog name: `smartcardLogon` → `Smartcard Logon`. */
function humanize(name: string): string {
    const spaced = name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').trim();
    return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/** What a picker needs, plus what the catalog could not confirm. */
export interface UsageCatalog {
    /** Canonical option values, for pickers and for `canonicalizeUsages`. */
    options: string[];
    /** Presentation only — never persist the result. */
    label: (value: string) => string;
    /** False until the catalog has been fetched at least once this session. */
    loaded: boolean;
    /**
     * Options this UI offers that the server's catalog does not contain.
     *
     * Selecting one of these produces a profile that cannot issue: the issuance path resolves
     * against the same catalog, finds nothing, and refuses with MCA-POL-000 — a message about the
     * profile's spelling, when the profile is fine and the catalog is short. Surfacing the
     * divergence where the choice is made is the difference between noticing it in the profile
     * editor and discovering it at enrollment.
     *
     * Empty on a healthy installation.
     */
    missingFromCatalog: string[];
}

/**
 * The standard key-usage vocabulary, read from the OID catalog.
 *
 * This did not exist, and its absence is what let a broken installation stay invisible. The EKU
 * picker has been catalog-backed for a while; the key-usage picker read a hardcoded list of nine
 * names and never asked the server anything. So a deployment whose catalog held no Standard rows
 * at all still rendered a complete, confident picker — and every certificate it was used to
 * request was refused at issuance.
 *
 * The built-in names remain the option list rather than being replaced by the catalog's, for the
 * same reason `useEkuCatalog` keeps its defaults: `canonicalizeUsages` DROPS any stored value
 * matching no option and the result is written back on save, so a catalog that is empty, slow or
 * briefly unreachable must not become a picker that silently strips usages from a profile someone
 * opens and saves. What changes is that the gap is now reported instead of papered over.
 */
export function useKeyUsageCatalog(): UsageCatalog {
    const [entries, setEntries] = useState<OidCatalogEntry[] | null>(cache);

    useEffect(() => {
        let active = true;
        loadCatalog().then((rows) => { if (active) setEntries(rows); });
        return () => { active = false; };
    }, []);

    const options = [...KEY_USAGE_OPTIONS];

    // Only meaningful once the fetch has resolved; before that every option would look missing.
    const known = new Set(
        (entries ?? [])
            .filter((e) => e.keyUsage === 'Standard')
            .map((e) => canonicalizeUsage(e.friendlyName)),
    );
    const missingFromCatalog = entries === null
        ? []
        : options.filter((o) => !known.has(canonicalizeUsage(o)));

    return {
        options,
        label: keyUsageLabel,
        loaded: entries !== null,
        missingFromCatalog,
    };
}

/**
 * Returns the effective EKU vocabulary: everything the catalog reports, unioned with the built-in
 * defaults so nothing the UI previously offered can disappear.
 */
export function useEkuCatalog(): EkuCatalog {
    const [entries, setEntries] = useState<OidCatalogEntry[] | null>(cache);

    useEffect(() => {
        let active = true;
        loadCatalog().then((rows) => { if (active) setEntries(rows); });
        return () => { active = false; };
    }, []);

    const extended = (entries ?? []).filter((e) => e.keyUsage === 'Extended' && !!e.oid);

    const options = [...DEFAULT_EKU_OPTIONS];
    const aliases: Record<string, string> = { ...DEFAULT_EKU_ALIASES };
    const labels: Record<string, string> = { ...DEFAULT_EKU_LABELS };

    for (const entry of extended) {
        if (!options.includes(entry.oid)) options.push(entry.oid);
        if (entry.friendlyName) {
            aliases[entry.friendlyName] = entry.oid;
            // A curated label wins; the catalog name is the fallback for anything new.
            if (!labels[entry.oid]) labels[entry.oid] = humanize(entry.friendlyName);
        }
    }

    // Which of the built-in defaults the catalog does not actually contain. Anything discovered
    // from the catalog is present by construction, so only the hardcoded base can diverge — and
    // that base is precisely what would otherwise hide an empty or partial catalog behind a
    // full-looking picker.
    const knownOids = new Set(extended.map((e) => e.oid));
    const missingFromCatalog = entries === null
        ? []
        : DEFAULT_EKU_OPTIONS.filter((oid) => !knownOids.has(oid));

    return {
        options,
        aliases,
        label: (oid: string) => labels[oid] ?? oid,
        loaded: entries !== null,
        missingFromCatalog,
    };
}
