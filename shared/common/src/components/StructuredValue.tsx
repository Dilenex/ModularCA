import React, { useMemo, useState } from 'react';
import {
    type StructuredValueOptions, type ValueNode, buildValueTree, isContainerNode, parseJsonText,
} from './structuredValueModel';

export interface StructuredValueProps extends Pick<StructuredValueOptions, 'maxDepth' | 'maxItems'> {
    /** An already parsed value. Ignored when `json` is given. */
    value?: unknown;
    /** JSON text, parsed here. Text that does not parse is shown as it is. */
    json?: string | null;
    /** Offer "Show raw JSON" for the original text. Default true. */
    rawToggle?: boolean;
    className?: string;
}

/** Nested containers start open down to this depth, when they are this small or smaller. */
const OPEN_DEPTH = 1;
const OPEN_SIZE = 12;

const containerSize = (n: ValueNode): number =>
    n.kind === 'object' ? n.entries.length : n.kind === 'list' ? n.items.length : n.kind === 'table' ? n.rows.length : 0;

const Leaf: React.FC<{ node: Extract<ValueNode, { kind: 'empty' | 'text' | 'truncated' }> }> = ({ node }) => {
    if (node.kind === 'empty') return <span className="text-xs text-ink-faint">{node.text}</span>;
    if (node.kind === 'truncated') {
        return (
            <span className="text-xs text-ink-muted">
                {node.summary}, too deeply nested to lay out:{' '}
                <span className="data-mono break-all text-ink">{node.raw}</span>
            </span>
        );
    }
    return (
        <span title={node.title}
            className={`text-ink ${node.mono ? 'data-mono break-all' : 'text-xs break-words'} ${node.multiline ? 'whitespace-pre-wrap' : ''}`}>
            {node.text}
        </span>
    );
};

const More: React.FC<{ count: number }> = ({ count }) =>
    count > 0 ? <p className="text-xs text-ink-muted">…and {count} more; see the raw JSON.</p> : null;

/** A nested container, collapsible behind its size. */
const Nested: React.FC<{ node: ValueNode; depth: number; label?: string }> = ({ node, depth, label }) => {
    if (!isContainerNode(node)) return <Leaf node={node} />;
    const open = depth <= OPEN_DEPTH && containerSize(node) <= OPEN_SIZE;
    return (
        <details open={open}>
            <summary className="cursor-pointer select-none text-xs text-ink-muted hover:text-ink">
                {label ? <>{label} · </> : null}{node.summary}
            </summary>
            <div className="mt-1 ml-1 pl-3 border-l border-line">
                <NodeView node={node} depth={depth} />
            </div>
        </details>
    );
};

const NodeView: React.FC<{ node: ValueNode; depth: number }> = ({ node, depth }) => {
    switch (node.kind) {
        case 'object':
            if (node.entries.length === 0) return <span className="text-xs text-ink-faint">(no fields)</span>;
            return (
                <dl className="space-y-1">
                    {node.entries.map((e, i) => (
                        isContainerNode(e.node) ? (
                            <div key={i}>
                                <dt className="text-xs text-ink-muted" title={e.key}>{e.label}</dt>
                                <dd className="mt-0.5"><Nested node={e.node} depth={depth + 1} /></dd>
                            </div>
                        ) : (
                            <div key={i} className="flex flex-wrap gap-x-3">
                                <dt className="text-xs text-ink-muted min-w-[8rem]" title={e.key}>{e.label}</dt>
                                <dd className="min-w-0 flex-1"><Leaf node={e.node} /></dd>
                            </div>
                        )
                    ))}
                    <More count={node.more} />
                </dl>
            );
        case 'list':
            if (node.items.length === 0) return <span className="text-xs text-ink-faint">(no items)</span>;
            return (
                <div>
                    <ul className="list-disc pl-4 space-y-0.5 marker:text-ink-faint">
                        {node.items.map((item, i) => (
                            <li key={i}>
                                {isContainerNode(item) ? <Nested node={item} depth={depth + 1} label={`Item ${i + 1}`} /> : <Leaf node={item} />}
                            </li>
                        ))}
                    </ul>
                    <More count={node.more} />
                </div>
            );
        case 'table':
            return (
                <div>
                    <div className="overflow-x-auto max-w-full">
                        <table className="text-xs border border-line">
                            <thead>
                                <tr className="bg-sunken">
                                    {node.columns.map((c) => (
                                        <th key={c.key} scope="col" title={c.key} className="px-2 py-1 text-left font-medium text-ink-muted border-b border-line">{c.label}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {node.rows.map((row, r) => (
                                    <tr key={r} className="border-b border-line last:border-b-0">
                                        {row.map((cell, c) => (
                                            <td key={c} className="px-2 py-1 align-top">
                                                {isContainerNode(cell) ? null : <Leaf node={cell} />}
                                            </td>
                                        ))}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    <More count={node.more} />
                </div>
            );
        default:
            return <Leaf node={node} />;
    }
};

/**
 * Renders a JSON value as nested label/value rows: objects as definition lists, arrays as lists
 * (or a table when they hold objects of the same primitive fields), primitives formatted. Nested
 * containers collapse; past `maxDepth` a container shows as compact JSON. Text only, never markup.
 * Shared so every view of server-written JSON (audit details first) reads the same way.
 */
export const StructuredValue: React.FC<StructuredValueProps> = ({ value, json, maxDepth, maxItems, rawToggle = true, className = '' }) => {
    const [showRaw, setShowRaw] = useState(false);
    const parsed = useMemo(() => (json == null ? { ok: true as const, value } : parseJsonText(json)), [json, value]);
    const tree = useMemo(() => (parsed.ok ? buildValueTree(parsed.value, { maxDepth, maxItems }) : null), [parsed, maxDepth, maxItems]);
    const raw = useMemo(() => {
        if (json != null) return json;
        try { return JSON.stringify(value, null, 2) ?? ''; } catch { return ''; }
    }, [json, value]);

    if (!tree) return <span className={`data-mono whitespace-pre-wrap break-all text-ink ${className}`}>{json}</span>;

    return (
        <div className={`min-w-0 break-normal space-y-1 ${className}`}>
            {isContainerNode(tree) ? <NodeView node={tree} depth={0} /> : <Leaf node={tree} />}
            {rawToggle && raw !== '' && (
                <div>
                    <button type="button" onClick={() => setShowRaw(!showRaw)} aria-expanded={showRaw}
                        className="text-xs text-accent-ink hover:underline">
                        {showRaw ? 'Hide raw JSON' : 'Show raw JSON'}
                    </button>
                    {showRaw && (
                        <pre className="mt-1 p-2 rounded bg-sunken border border-line data-mono text-ink whitespace-pre-wrap break-all max-h-80 overflow-auto">{raw}</pre>
                    )}
                </div>
            )}
        </div>
    );
};
