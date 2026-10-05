/**
 * Coloured status pill. The two copies differed only in comment wording, and userui's was missing its React import.
 *
 * No default export: shared/README.md rule 3.
 */

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

export function StatusBadge({ status, label }: StatusBadgeProps) {
    return (
        <span className={`inline-flex items-center px-1.5 py-px text-xs font-medium rounded-sm border ${colors[status] || colors.disabled}`}>
            {label || status}
        </span>
    );
}
