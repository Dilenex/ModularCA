import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
    type ValueNode, buildValueTree, formatPrimitive, humanizeKey, parseJsonContainer, parseJsonText, uniformColumns,
} from '@shared/components/structuredValueModel';

/**
 * The pure half of StructuredValue, the renderer for audit details and other server-written
 * JSON. Audit details carry attacker-influenced strings, so the tree must hold them as text.
 */

const text = (n: ValueNode) => {
    if (n.kind !== 'text' && n.kind !== 'empty') throw new Error(`expected a leaf, got ${n.kind}`);
    return n.text;
};

describe('formatPrimitive', () => {
    it('reads booleans as Yes/No and null as a dash', () => {
        expect(text(formatPrimitive(true))).toBe('Yes');
        expect(text(formatPrimitive(false))).toBe('No');
        expect(formatPrimitive(null)).toEqual({ kind: 'empty', text: '—' });
        expect(formatPrimitive(undefined)).toEqual({ kind: 'empty', text: '—' });
        expect(formatPrimitive('')).toEqual({ kind: 'empty', text: '(empty)' });
        expect(text(formatPrimitive(0))).toBe('0');
    });

    it('formats ISO timestamps and keeps the raw value as the title', () => {
        const n = formatPrimitive('2026-10-04T12:34:56.789Z', 'at', { formatDate: (d) => `D:${d.toISOString()}` });
        expect(n).toMatchObject({ kind: 'text', text: 'D:2026-10-04T12:34:56.789Z', title: '2026-10-04T12:34:56.789Z' });
        expect(formatPrimitive('2026-10-04T12:34:56+02:00', undefined, { formatDate: () => 'x' })).toMatchObject({ text: 'x' });
        // Not a real date: left as written.
        expect(formatPrimitive('2026-13-45T99:99Z', undefined, { formatDate: () => 'x' })).toMatchObject({ text: '2026-13-45T99:99Z' });
        expect(formatPrimitive('2026-10-04', undefined, { formatDate: () => 'x' })).toMatchObject({ text: '2026-10-04' });
    });

    it('sets GUIDs, long hex and id-like keys in mono', () => {
        expect(formatPrimitive('0b6f3f0e-1111-4c4c-9a9a-000000000001')).toMatchObject({ mono: true });
        expect(formatPrimitive('3A9F00C1D2E3F4A5B6C7')).toMatchObject({ mono: true });
        expect(formatPrimitive('3a:9f:00:c1:d2:e3:f4:a5')).toMatchObject({ mono: true });
        expect(formatPrimitive('deadbeef')).toMatchObject({ mono: false });
        expect(formatPrimitive('Acme Corp')).toMatchObject({ mono: false });
        expect(formatPrimitive('12', 'caId')).toMatchObject({ mono: true });
        expect(formatPrimitive('10.0.0.1', 'sourceIp')).toMatchObject({ mono: true });
        expect(formatPrimitive('yes', 'valid')).toMatchObject({ mono: false });
    });

    it('marks multi-line text', () => {
        expect(formatPrimitive('a\nb')).toMatchObject({ multiline: true, text: 'a\nb' });
    });
});

describe('humanizeKey', () => {
    it('splits identifiers and keeps acronyms', () => {
        expect(humanizeKey('caId')).toBe('CA ID');
        expect(humanizeKey('certSerialNumber')).toBe('Cert serial number');
        expect(humanizeKey('IPAddress')).toBe('IP address');
        expect(humanizeKey('old_value')).toBe('Old value');
        expect(humanizeKey('detailsJson')).toBe('Details JSON');
    });

    it('leaves keys that are not identifiers as written', () => {
        expect(humanizeKey('CN=Admins,DC=example,DC=com')).toBe('CN=Admins,DC=example,DC=com');
        expect(humanizeKey('x-forwarded-for')).toBe('x-forwarded-for');
    });
});

describe('parseJsonText and parseJsonContainer', () => {
    it('parses JSON and unwraps a double-encoded object once', () => {
        expect(parseJsonText('{"a":1}')).toEqual({ ok: true, value: { a: 1 } });
        expect(parseJsonText(JSON.stringify(JSON.stringify({ a: 1 })))).toEqual({ ok: true, value: { a: 1 } });
        expect(parseJsonText('"plain"')).toEqual({ ok: true, value: 'plain' });
        expect(parseJsonText('{bad')).toEqual({ ok: false });
    });

    it('finds objects and arrays held in strings, nothing else', () => {
        expect(parseJsonContainer(' {"a":1} ')).toEqual({ a: 1 });
        expect(parseJsonContainer('[{"type":"dns","value":"a.example"}]')).toEqual([{ type: 'dns', value: 'a.example' }]);
        expect(parseJsonContainer('"x"')).toBeUndefined();
        expect(parseJsonContainer('42')).toBeUndefined();
        expect(parseJsonContainer('{bad}')).toBeUndefined();
        expect(parseJsonContainer('[x] not json')).toBeUndefined();
        expect(parseJsonContainer({ a: 1 })).toBeUndefined();
    });
});

describe('buildValueTree', () => {
    it('renders objects as labelled entries', () => {
        const tree = buildValueTree({ caId: 'abc', revoked: true, reason: null });
        expect(tree.kind).toBe('object');
        if (tree.kind !== 'object') return;
        expect(tree.summary).toBe('3 fields');
        expect(tree.entries.map((e) => [e.key, e.label, text(e.node)])).toEqual([
            ['caId', 'CA ID', 'abc'], ['revoked', 'Revoked', 'Yes'], ['reason', 'Reason', '—'],
        ]);
    });

    it('renders primitive arrays as lists and uniform objects as tables', () => {
        const list = buildValueTree(['a.example', 'b.example']);
        expect(list).toMatchObject({ kind: 'list', summary: '2 items' });

        const table = buildValueTree([{ type: 'dns', value: 'a.example' }, { type: 'ip', value: '10.0.0.1', extra: true }]);
        expect(table.kind).toBe('table');
        if (table.kind !== 'table') return;
        expect(table.columns.map((c) => c.label)).toEqual(['Type', 'Value', 'Extra']);
        expect(table.rows.map((r) => r.map(text))).toEqual([['dns', 'a.example', '—'], ['ip', '10.0.0.1', 'Yes']]);
    });

    it('keeps objects with nested values as a list, not a table', () => {
        expect(uniformColumns([{ a: 1 }, { a: { b: 2 } }])).toBeNull();
        expect(uniformColumns([{ a: 1 }])).toEqual(['a']);
        expect(uniformColumns([])).toBeNull();
        expect(uniformColumns([{}, {}])).toBeNull();
        expect(uniformColumns([{ a: 1 }, 'x'])).toBeNull();
        expect(buildValueTree([{ a: 1 }, { a: { b: 2 } }]).kind).toBe('list');
    });

    it('stops at the depth limit with compact JSON', () => {
        const tree = buildValueTree({ a: { b: { c: 1 } } }, { maxDepth: 1 });
        if (tree.kind !== 'object') throw new Error('object expected');
        const a = tree.entries[0].node;
        if (a.kind !== 'object') throw new Error('a should still be laid out');
        expect(a.entries[0].node).toEqual({ kind: 'truncated', summary: '1 field', raw: '{"c":1}' });

        const flat = buildValueTree({ a: [1] }, { maxDepth: 0 });
        if (flat.kind !== 'object') throw new Error('object expected');
        expect(flat.entries[0].node).toMatchObject({ kind: 'truncated', raw: '[1]' });
    });

    it('survives deep nesting under the default limit', () => {
        let deep: unknown = 'bottom';
        for (let i = 0; i < 500; i++) deep = { n: deep };
        expect(() => buildValueTree(deep)).not.toThrow();
    });

    it('shows at most maxItems per container and counts the rest', () => {
        const tree = buildValueTree(Array.from({ length: 60 }, (_, i) => i), { maxItems: 50 });
        expect(tree).toMatchObject({ kind: 'list', more: 10, summary: '60 items' });
        if (tree.kind === 'list') expect(tree.items).toHaveLength(50);
    });

    it('holds markup as text, verbatim, in values and keys', () => {
        const payload = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
        const parsed = parseJsonText(JSON.stringify({ [payload]: payload, list: [payload] }));
        if (!parsed.ok) throw new Error('should parse');
        const tree = buildValueTree(parsed.value);
        if (tree.kind !== 'object') throw new Error('object expected');
        expect(tree.entries[0]).toMatchObject({ key: payload, label: payload });
        expect(text(tree.entries[0].node)).toBe(payload);
        const list = tree.entries[1].node;
        expect(list.kind === 'list' && text(list.items[0])).toBe(payload);
    });

    it('treats a __proto__ key as an ordinary entry', () => {
        const parsed = parseJsonText('{"__proto__": {"polluted": true}, "a": 1}');
        if (!parsed.ok) throw new Error('should parse');
        const tree = buildValueTree(parsed.value);
        if (tree.kind !== 'object') throw new Error('object expected');
        expect(tree.entries.map((e) => e.key)).toEqual(['__proto__', 'a']);
        expect(({} as any).polluted).toBeUndefined();
    });
});

describe('StructuredValue component', () => {
    it('never renders markup from data', () => {
        const source = readFileSync(resolve(__dirname, '../../../../shared/common/src/components/StructuredValue.tsx'), 'utf8');
        expect(source).not.toMatch(/dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML/);
    });
});
