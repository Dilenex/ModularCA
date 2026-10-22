import React from 'react';
import type { ConstraintGroup } from '../pages/profileConstraints';

/// <summary>
/// What the profiles chosen beside it impose, a group to a profile: each group names what it is
/// about and the profile it comes from, then lists its facts as label and value.
/// </summary>
export const ConstraintPanel: React.FC<{
    groups: ConstraintGroup[];
    /** Shown while there is nothing to list yet. */
    empty: string;
    /** A line under the groups for something still being fetched. */
    pending?: string | null;
}> = ({ groups, empty, pending }) => (
    <div className="space-y-4 text-xs">
        {groups.length === 0 && !pending && <p className="text-ink-muted">{empty}</p>}
        {groups.map((group) => (
            <section key={group.title} aria-label={group.title}>
                <h4 className="flex flex-wrap items-baseline gap-x-2 mb-1">
                    <span className="label-caps">{group.title}</span>
                    {group.from && <span className="text-ink-muted truncate">{group.from}</span>}
                </h4>
                <dl className="grid grid-cols-[minmax(0,9.5rem)_minmax(0,1fr)] gap-x-3 gap-y-0.5">
                    {group.lines.map((line, i) => (
                        <React.Fragment key={`${line.label}-${i}`}>
                            <dt className="text-ink-muted">{line.label}</dt>
                            <dd className={`break-words ${line.tone === 'warn' ? 'text-warn' : 'text-ink'}`}>{line.value}</dd>
                        </React.Fragment>
                    ))}
                </dl>
            </section>
        ))}
        {pending && <p className="text-ink-muted">{pending}</p>}
    </div>
);
