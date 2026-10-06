import React from 'react';

interface DetailFieldProps {
    label: string;
    value: React.ReactNode;
    mono?: boolean;
}

/**
 * One label and its value. The label column has a fixed width, so the values of a list of
 * fields start on one line whatever the labels say. Where the field is given too little room
 * for two columns, the label sits above its value.
 */
export function DetailField({ label, value, mono }: DetailFieldProps) {
    if (value === null || value === undefined || value === '') return null;
    return (
        <div className="@container">
            <div className="grid grid-cols-1 @[18rem]:grid-cols-[10rem_minmax(0,1fr)] gap-x-3 items-baseline py-1">
                <span className="label-caps [overflow-wrap:anywhere]">{label}</span>
                <span className={`text-ink min-w-0 ${mono ? 'data-mono break-all' : 'text-sm [overflow-wrap:anywhere]'}`}>{value}</span>
            </div>
        </div>
    );
}
