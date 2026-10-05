/**
 * A cert profile's CT logs as a checklist over the CT log catalog
 * (GET /api/v1/admin/ct-logs/options). Pure, so tests/modularca.web.tests covers it.
 *
 * `CtLogIds` holds internal CT log ids (CtLogEntity.Id), not RFC 6962 LogIDs. Blank means every
 * log enabled at issuance (CtSubmissionService); a list means those logs, skipping any that are
 * disabled, so a list of only disabled logs submits nothing. The server refuses ids naming no log
 * (AdminCertProfileController), so an unknown stored id must be removed before Save.
 */
import type { CheckboxOption } from '@shared/components/checkboxListModel';
import { parseListField } from './profileFormCore';

/** One CT log as the options endpoint returns it. */
export interface CtLogChoice {
    id: string;
    name: string;
    url: string;
    enabled: boolean;
}

/** The catalog from the options endpoint, tolerating a missing or odd response. */
export const ctLogChoicesFromResponse = (data: unknown): CtLogChoice[] =>
    (Array.isArray(data) ? data : []).filter((l) => l && typeof l.id === 'string').map((l) => ({
        id: String(l.id), name: String(l.name ?? ''), url: String(l.url ?? ''), enabled: l.enabled !== false,
    }));

const sameId = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** The stored ids, in order, once each; null or blank is none. A value that is not a JSON array is read item by item. */
export const ctLogIdsFromStored = (stored: unknown): string[] => {
    const out: string[] = [];
    for (const raw of parseListField(stored)) {
        const id = raw.trim();
        if (id && !out.some((x) => sameId(x, id))) out.push(id);
    }
    return out;
};

/** The body value: null for none (so a child profile inherits its parent's list), else a JSON array. */
export const ctLogIdsToBody = (ids: readonly string[]): string | null => (ids.length ? JSON.stringify(ids) : null);

/** Checkbox options: the log's name, an Enabled or Disabled badge, and its URL. */
export const ctLogOptions = (logs: readonly CtLogChoice[]): CheckboxOption[] => logs.map((l) => ({
    value: l.id,
    label: l.name || l.url || l.id,
    badge: l.enabled ? { label: 'Enabled', tone: 'ok' } : { label: 'Disabled', tone: 'muted' },
    description: l.enabled ? l.url : `${l.url} (skipped at issuance while disabled)`,
}));

/**
 * The stored ids no log in the catalog has, in the catalog's spelling of the id otherwise. Empty
 * when the catalog could not be loaded (null), since nothing can then be judged.
 */
export const unknownCtLogIds = (ids: readonly string[], logs: readonly CtLogChoice[] | null): string[] =>
    logs ? ids.filter((id) => !logs.some((l) => sameId(l.id, id))) : [];

/** Stored ids rewritten in the catalog's spelling, so the checkboxes match regardless of case. */
export const canonicalCtLogIds = (ids: readonly string[], logs: readonly CtLogChoice[] | null): string[] =>
    ids.map((id) => logs?.find((l) => sameId(l.id, id))?.id ?? id);

/** One stored id for display: the log's name (and Disabled when it is), or "unknown log". */
export const ctLogDisplay = (id: string, logs: readonly CtLogChoice[] | null): { text: string; tone: 'ok' | 'muted' | 'crit' } => {
    if (!logs) return { text: id, tone: 'ok' };
    const log = logs.find((l) => sameId(l.id, id));
    if (!log) return { text: `Unknown log (${id})`, tone: 'crit' };
    return log.enabled ? { text: log.name, tone: 'ok' } : { text: `${log.name} (disabled, skipped)`, tone: 'muted' };
};

/** Whether "Only these logs" names logs of which none is enabled, so nothing would be submitted. */
export const noEnabledLogChosen = (ids: readonly string[], logs: readonly CtLogChoice[] | null): boolean =>
    !!logs && ids.length > 0 && !ids.some((id) => logs.some((l) => sameId(l.id, id) && l.enabled));
