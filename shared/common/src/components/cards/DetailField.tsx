/**
 * Label-over-value pair used throughout the detail pages. Byte-identical in both SPAs.
 *
 * No default export: shared/README.md rule 3.
 */
import React from 'react';

interface DetailFieldProps {
    label: string;
    value: React.ReactNode;
    mono?: boolean;
}

export function DetailField({ label, value, mono }: DetailFieldProps) {
    if (value === null || value === undefined || value === '') return null;

    return (
        <div className="flex gap-2 py-1">
            <span className="label-caps min-w-[120px] flex-shrink-0 pt-0.5">{label}</span>
            <span className={`text-ink break-all ${mono ? 'data-mono' : 'text-xs'}`}>
                {value}
            </span>
        </div>
    );
}
