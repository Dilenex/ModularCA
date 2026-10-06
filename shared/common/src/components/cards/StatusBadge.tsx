/**
 * The two small labels the consoles put beside a name.
 *
 * StatusBadge says what state a thing is in, and colour belongs to it alone: green is working,
 * amber needs attention, red is refused or revoked, blue is waiting, grey is off. Tag says what
 * kind of thing it is (Root, Leaf, Built-in, a protocol) and is always neutral, so a row of type
 * and status never reads as two statuses.
 *
 * No default export: shared/README.md rule 3.
 */

import { badgeText } from '../../badgeText';

interface StatusBadgeProps {
    status: 'active' | 'revoked' | 'expired' | 'held' | 'pending' | 'locked' | 'disabled' | 'enabled';
    label?: string;
}

// Status tokens from ledger.css: each solid tone holds 4.5:1 on its own soft tint in both themes.
const colors: Record<string, string> = {
    active:   'bg-ok-soft text-ok border-ok/40',
    enabled:  'bg-ok-soft text-ok border-ok/40',
    revoked:  'bg-crit-soft text-crit border-crit/40',
    locked:   'bg-crit-soft text-crit border-crit/40',
    disabled: 'bg-sunken text-ink-muted border-line',
    expired:  'bg-warn-soft text-warn border-warn/40',
    held:     'bg-warn-soft text-warn border-warn/40',
    pending:  'bg-info-soft text-info border-info/40',
};

const shape = 'inline-flex items-center px-1.5 py-px text-xs font-medium rounded-sm border whitespace-nowrap';

export function StatusBadge({ status, label }: StatusBadgeProps) {
    return (
        <span className={`${shape} ${colors[status] || colors.disabled}`}>
            {badgeText(label || status)}
        </span>
    );
}

interface TagProps {
    label: string;
    /** `accent` marks the one of several that is in force, such as the default profile. */
    tone?: 'neutral' | 'accent';
}

export function Tag({ label, tone = 'neutral' }: TagProps) {
    const color = tone === 'accent' ? 'bg-accent-soft text-accent-ink border-accent/40' : 'bg-sunken text-ink-muted border-line';
    return <span className={`${shape} ${color}`}>{badgeText(label)}</span>;
}
