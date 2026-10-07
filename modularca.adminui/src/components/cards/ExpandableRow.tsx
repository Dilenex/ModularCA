import React, { useState } from 'react';
import { Chevron } from '@shared/components/Chevron';

interface Action {
    label: string;
    onClick: () => void;
    variant?: 'default' | 'danger' | 'primary';
    confirm?: string;
}

interface ExpandableRowProps<T> {
    item: T;
    isExpanded: boolean;
    onToggle: () => void;
    renderSummary: (item: T) => React.ReactNode;
    renderDetail: (item: T) => React.ReactNode;
    actions?: (item: T) => Action[];
}

export default function ExpandableRow<T>({
    item,
    isExpanded,
    onToggle,
    renderSummary,
    renderDetail,
    actions,
}: ExpandableRowProps<T>) {
    const [confirming, setConfirming] = useState<string | null>(null);

    const variantClasses: Record<string, string> = {
        default: 'bg-raised border border-line-strong hover:bg-hover text-ink',
        danger: 'bg-crit hover:bg-crit-hover text-on-accent',
        primary: 'bg-accent hover:bg-accent-hover text-on-accent',
    };

    const handleAction = (action: Action) => {
        if (action.confirm && confirming !== action.label) {
            setConfirming(action.label);
            setTimeout(() => setConfirming(null), 3000);
            return;
        }
        setConfirming(null);
        action.onClick();
    };

    return (
        <div className="border-b border-line last:border-b-0">
            <div
                className="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-hover transition-colors"
                onClick={onToggle}
            >
                <div className="flex-1 text-sm text-ink truncate">
                    {renderSummary(item)}
                </div>
                <span className="text-ink-muted ml-2 text-xs">
                    <Chevron direction={(isExpanded) ? 'up' : 'down'} className="w-3 h-3" />
                </span>
            </div>

            {isExpanded && (
                <div className="px-4 pb-4 bg-sunken border-t border-line">
                    <div className="pt-3 text-sm text-ink">
                        {renderDetail(item)}
                    </div>

                    {actions && (
                        <div className="flex gap-2 mt-3 pt-3 border-t border-line">
                            {actions(item).map((action) => (
                                <button
                                    key={action.label}
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        handleAction(action);
                                    }}
                                    className={`px-3 py-1 text-xs rounded transition-colors ${variantClasses[action.variant || 'default']}`}
                                >
                                    {confirming === action.label ? `Confirm ${action.label}?` : action.label}
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
