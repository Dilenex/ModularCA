import { describe, expect, it } from 'vitest';
import {
    type TypedEntryType, addEntryRow, canonicalList, entriesFromList, entriesToList, findEntryType, findTypedEntryProblems,
    formatTypedEntry, hasTypedEntryProblems, insertPastedEntries, parseTypedEntry, pastedTypedValue, removeEntryRow,
    sameEntryLists, splitPastedEntries, typedEntryError, updateEntryRow,
} from '@shared/components/typedEntryList';

/**
 * The logic behind TypedEntryListEditor: rows of a type and a value, read from and written to
 * `TYPE:value` strings. Types match in any case on input and are written in the caller's spelling.
 */

const TYPES: TypedEntryType[] = [
    { value: 'DNS', label: 'DNS', validate: (v) => (v.includes(' ') ? 'no spaces' : null) },
    { value: 'IP', label: 'IP' },
    { value: 'Email', label: 'Email', aliases: ['RFC822'] },
];

describe('reading and writing entries', () => {
    it('matches the type in any case and writes the canonical spelling', () => {
        expect(parseTypedEntry('dns:example.com', TYPES)).toEqual({ type: 'DNS', value: 'example.com' });
        expect(parseTypedEntry('EMAIL:a@b.example', TYPES)).toEqual({ type: 'Email', value: 'a@b.example' });
        expect(parseTypedEntry('rfc822:a@b.example', TYPES)).toEqual({ type: 'Email', value: 'a@b.example' });
        expect(formatTypedEntry(parseTypedEntry('email: a@b.example ', TYPES))).toBe('Email:a@b.example');
    });

    it('keeps an unknown prefix as typed, and an untyped value with no type', () => {
        expect(parseTypedEntry('URI:https://x', TYPES)).toEqual({ type: 'URI', value: 'https://x' });
        expect(parseTypedEntry('example.com', TYPES)).toEqual({ type: '', value: 'example.com' });
    });

    it('gives the whole text to the default type when there is no known prefix', () => {
        expect(parseTypedEntry('2001:db8::1', TYPES, 'IP')).toEqual({ type: 'IP', value: '2001:db8::1' });
        expect(parseTypedEntry('DNS:a.example', TYPES, 'IP')).toEqual({ type: 'DNS', value: 'a.example' });
    });

    it('round-trips a list and drops rows without a value', () => {
        const rows = entriesFromList(['DNS:a.example', 'ip:10.0.0.1'], TYPES);
        expect(entriesToList([...rows, { type: 'DNS', value: '  ' }])).toEqual(['DNS:a.example', 'IP:10.0.0.1']);
        expect(entriesFromList(null, TYPES)).toEqual([]);
    });

    it('compares lists ignoring type case and spacing', () => {
        expect(sameEntryLists(['email:a@b.example'], ['Email: a@b.example'], TYPES)).toBe(true);
        expect(sameEntryLists(['DNS:a.example'], ['DNS:b.example'], TYPES)).toBe(false);
        expect(canonicalList(['dns:A.example'], TYPES)).toEqual(['DNS:A.example']);
    });

    it('finds a type by value or alias', () => {
        expect(findEntryType(TYPES, 'rfc822')?.value).toBe('Email');
        expect(findEntryType(TYPES, '')).toBeUndefined();
    });
});

describe('validation', () => {
    it('never flags a blank row, which is dropped on save', () => {
        expect(typedEntryError({ type: 'DNS', value: '' }, TYPES)).toBeNull();
    });

    it('flags a missing or unknown type, a type not allowed, and a failed validator', () => {
        expect(typedEntryError({ type: '', value: 'x' }, TYPES)).toMatch(/no type/);
        expect(typedEntryError({ type: 'URI', value: 'x' }, TYPES)).toMatch(/not a supported type/);
        expect(typedEntryError({ type: 'IP', value: '1.2.3.4' }, TYPES, { allowedTypes: ['DNS'] })).toMatch(/not accepted/);
        expect(typedEntryError({ type: 'DNS', value: 'a b' }, TYPES)).toBe('no spaces');
    });

    it('reports problems with their row index', () => {
        const rows = [{ type: 'DNS', value: 'ok.example' }, { type: 'DNS', value: 'bad one' }];
        expect(findTypedEntryProblems(rows, TYPES)).toEqual([{ index: 1, entry: rows[1], message: 'no spaces' }]);
        expect(hasTypedEntryProblems(rows, TYPES)).toBe(true);
        expect(hasTypedEntryProblems(rows.slice(0, 1), TYPES)).toBe(false);
    });
});

describe('editing and paste-to-split', () => {
    it('adds, updates and removes rows', () => {
        let rows = addEntryRow([], 'DNS');
        rows = updateEntryRow(rows, 0, { value: 'a.example' });
        rows = addEntryRow(rows, 'IP');
        expect(rows).toEqual([{ type: 'DNS', value: 'a.example' }, { type: 'IP', value: '' }]);
        expect(removeEntryRow(rows, 0)).toEqual([{ type: 'IP', value: '' }]);
    });

    it('splits pasted lines and JSON arrays, not single values or commas', () => {
        expect(splitPastedEntries('a.example\r\nDNS:b.example\n\n')).toEqual(['a.example', 'DNS:b.example']);
        expect(splitPastedEntries('["DNS:a.example", "IP:10.0.0.0/8"]')).toEqual(['DNS:a.example', 'IP:10.0.0.0/8']);
        expect(splitPastedEntries('O=Acme, Inc.')).toBeNull();
        expect(splitPastedEntries('a.example')).toBeNull();
    });

    it('puts pasted entries in place of a blank row, using its type for unprefixed lines', () => {
        const rows = [{ type: 'DNS', value: 'keep.example' }, { type: 'IP', value: '' }];
        expect(insertPastedEntries(rows, 1, ['10.0.0.1', 'DNS:x.example'], TYPES)).toEqual([
            { type: 'DNS', value: 'keep.example' }, { type: 'IP', value: '10.0.0.1' }, { type: 'DNS', value: 'x.example' },
        ]);
    });

    it('inserts after a row that already has a value', () => {
        const rows = [{ type: 'DNS', value: 'a.example' }, { type: 'DNS', value: 'z.example' }];
        expect(insertPastedEntries(rows, 0, ['b.example', 'c.example'], TYPES).map((r) => r.value))
            .toEqual(['a.example', 'b.example', 'c.example', 'z.example']);
    });

    it('reads a single pasted TYPE:value only when the prefix is known', () => {
        expect(pastedTypedValue('ip:10.0.0.1', TYPES)).toEqual({ type: 'IP', value: '10.0.0.1' });
        expect(pastedTypedValue('2001:db8::1', TYPES)).toBeNull();
        expect(pastedTypedValue('https://x', TYPES)).toBeNull();
    });
});
