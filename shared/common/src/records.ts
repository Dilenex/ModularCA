import type React from 'react';
import type { DataTableColumn } from './components/DataTable';

/**
 * A record descriptor: one description of an entity from which its three views render, the
 * row in a list, the drawer for a quick look and light action, and (for the few entities that
 * have one) the full page.
 *
 * The 576 hand-placed detail fields across the console are the cost of not having this. A
 * descriptor is data: columns for the table, sections of fields for the drawer, an audit
 * filter so the entity's activity shows without new endpoints, related lists, and actions.
 * Editing in the drawer (`edit`) is the next phase; the shape is here so descriptors can be
 * written once.
 */

/** A label/value pair, as the console's detail views have always rendered them. */
export interface FieldSpec<T> {
    label: string;
    /** The value to show. Null, undefined and empty strings hide the field. */
    value: (row: T) => React.ReactNode;
    /** Monospace rendering, for serials, OIDs, hashes and ids. */
    mono?: boolean;
    /** Show a copy button beside the value (string values only). */
    copyable?: boolean;
}

export interface RecordSection<T> {
    title?: string;
    fields: FieldSpec<T>[];
}

/** A status chip: what the row and the drawer header show. */
export interface RecordStatus {
    label: string;
    tone: 'ok' | 'warn' | 'bad' | 'neutral';
}

/** Which audit rows belong to the entity: the audit tab, with the list's own filters. */
export interface RecordAudit<T> {
    /** The audit tab the rows live on. Only General is queryable by target today. */
    tab: 'General';
    /** The entity as audit rows name it. */
    target: (row: T) => { type: string; id: string } | null;
}

/** A nested list of other records that belong with this one. */
export interface RecordRelated<T> {
    title: string;
    /** Loads the related rows. */
    load: (row: T) => Promise<unknown[]>;
    /** How to render them; the related list is a nested DataTable over this descriptor. */
    descriptor: RecordDescriptor<any>;
    /** A page listing the same rows, offered as a link when present. */
    listPath?: (row: T) => string;
}

export interface RecordAction<T> {
    label: string;
    run: (row: T) => Promise<void> | void;
    /** Grey the action out for rows it does not apply to. */
    enabled?: (row: T) => boolean;
    tone?: 'default' | 'primary' | 'danger';
}

export interface RecordDescriptor<T> {
    /** A stable name for the entity, for table ids and keys. */
    kind: string;
    /** The row's identity. */
    key: (row: T) => string;
    title: (row: T) => string;
    status?: (row: T) => RecordStatus;
    columns: DataTableColumn<T>[];
    /** Drives the drawer's overview and the page. */
    sections: RecordSection<T>[];
    audit?: RecordAudit<T>;
    related?: RecordRelated<T>[];
    actions?: RecordAction<T>[];
    /** Present only for entities with a full page. */
    page?: { path: (row: T) => string };
}

/** Tailwind classes for a status tone, matching the console's badges. */
export function statusToneClass(tone: RecordStatus['tone']): string {
    switch (tone) {
        case 'ok': return 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700';
        case 'warn': return 'bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-700';
        case 'bad': return 'bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700';
        default: return 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600';
    }
}
