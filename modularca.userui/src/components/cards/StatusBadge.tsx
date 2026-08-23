interface StatusBadgeProps {
    status: 'active' | 'revoked' | 'expired' | 'held' | 'pending' | 'locked' | 'disabled' | 'enabled';
    label?: string;
}

// Light-mode uses tint-50 / text-800 for WCAG-AA contrast; dark-mode preserves
// the existing tint-900/50 translucent chips.
const colors: Record<string, string> = {
    active:   'bg-green-50 text-green-800 border-green-300 dark:bg-green-900/50 dark:text-green-300 dark:border-green-700',
    enabled:  'bg-green-50 text-green-800 border-green-300 dark:bg-green-900/50 dark:text-green-300 dark:border-green-700',
    revoked:  'bg-red-50 text-red-800 border-red-300 dark:bg-red-900/50 dark:text-red-300 dark:border-red-700',
    locked:   'bg-red-50 text-red-800 border-red-300 dark:bg-red-900/50 dark:text-red-300 dark:border-red-700',
    disabled: 'bg-gray-100 text-gray-700 border-gray-300 dark:bg-gray-700/50 dark:text-gray-400 dark:border-gray-600',
    expired:  'bg-yellow-50 text-yellow-800 border-yellow-300 dark:bg-yellow-900/50 dark:text-yellow-300 dark:border-yellow-700',
    held:     'bg-orange-50 text-orange-800 border-orange-300 dark:bg-orange-900/50 dark:text-orange-300 dark:border-orange-700',
    pending:  'bg-blue-50 text-blue-800 border-blue-300 dark:bg-blue-900/50 dark:text-blue-300 dark:border-blue-700',
};

export default function StatusBadge({ status, label }: StatusBadgeProps) {
    return (
        <span className={`inline-block px-2 py-0.5 text-xs rounded border ${colors[status] || colors.disabled}`}>
            {label || status}
        </span>
    );
}
