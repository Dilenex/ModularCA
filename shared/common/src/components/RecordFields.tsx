import React, { useState } from 'react';
import { DetailField } from './cards/DetailField';
import type { RecordSection } from '../records';

/**
 * Renders a descriptor's sections as label/value fields. The one place DetailField is called
 * for descriptor-driven views; a drawer and a page differ only in what surrounds this.
 */
export function RecordFields<T>({ sections, row }: { sections: RecordSection<T>[]; row: T }) {
    return (
        <div className="space-y-4">
            {sections.map((section, i) => {
                const rendered = section.fields
                    .map((f) => ({ f, v: f.value(row) }))
                    .filter(({ v }) => v !== null && v !== undefined && v !== '');
                if (rendered.length === 0) return null;
                return (
                    <section key={section.title ?? i}>
                        {section.title && <h4 className="text-[11px] font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-1">{section.title}</h4>}
                        <div className="text-sm">
                            {rendered.map(({ f, v }) => (
                                <DetailField
                                    key={f.label}
                                    label={f.label}
                                    mono={f.mono}
                                    value={f.copyable && typeof v === 'string' ? <Copyable text={v} /> : v}
                                />
                            ))}
                        </div>
                    </section>
                );
            })}
        </div>
    );
}

const Copyable: React.FC<{ text: string }> = ({ text }) => {
    const [copied, setCopied] = useState(false);
    const copy = async () => {
        try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200); } catch { /* clipboard unavailable */ }
    };
    return (
        <span className="inline-flex items-center gap-1.5 min-w-0">
            <span className="break-all">{text}</span>
            <button type="button" onClick={copy} title="Copy" aria-label={`Copy ${text}`} className="text-[10px] px-1 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:text-gray-900 dark:hover:text-white flex-shrink-0">
                {copied ? 'copied' : 'copy'}
            </button>
        </span>
    );
};
