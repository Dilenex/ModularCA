import { useEffect, useState } from 'react';
import { apiGet } from '../api/client';
import {
    DEFAULT_EKU_OPTIONS, DEFAULT_EKU_LABELS, DEFAULT_EKU_ALIASES,
} from '../pages/profileHelpers';

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

    return {
        options,
        aliases,
        label: (oid: string) => labels[oid] ?? oid,
        loaded: entries !== null,
    };
}
