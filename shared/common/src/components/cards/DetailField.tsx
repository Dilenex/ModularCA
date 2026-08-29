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
            <span className="text-gray-600 text-xs min-w-[120px] flex-shrink-0">{label}</span>
            <span className={`text-gray-800 dark:text-gray-200 text-xs break-all ${mono ? 'font-mono' : ''}`}>
                {value}
            </span>
        </div>
    );
}
