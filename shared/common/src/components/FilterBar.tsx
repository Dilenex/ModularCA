import React from 'react';

/*
 * One layout for the filters above a table: a single wrapping row, the search box first and
 * growing, every other control under a small caps label. Pages had three different layouts
 * (labels inline with a colon, labels above, no labels at all).
 *
 * No default export: shared/README.md rule 3.
 */

/** The look of every filter control: text inputs, date inputs and selects alike. */
export const filterControlClass =
    'px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent disabled:opacity-50';

export function FilterBar({ children }: { children: React.ReactNode }) {
    return <div className="flex flex-wrap gap-3 items-end">{children}</div>;
}

interface FilterFieldProps {
    label: string;
    /** The search box: takes the room the other controls leave. */
    grow?: boolean;
    children: React.ReactNode;
}

export function FilterField({ label, grow, children }: FilterFieldProps) {
    return (
        <label className={`flex flex-col gap-1 ${grow ? 'flex-1 min-w-[250px]' : ''}`}>
            <span className="label-caps">{label}</span>
            {children}
        </label>
    );
}
