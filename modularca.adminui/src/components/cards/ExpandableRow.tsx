import React, { useState } from 'react';
import { Chevron } from '@shared/components/Chevron';

interface Action {
    label: string;
    onClick: () => void;
    variant?: 'default' | 'danger' | 'success';
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
        default: 'bg-gray-600 hover:bg-gray-400 dark:hover:bg-gray-500 text-gray-900 dark:text-white',
        danger: 'bg-red-700 hover:bg-red-600 text-gray-900 dark:text-white',
        success: 'bg-green-700 hover:bg-green-600 text-gray-900 dark:text-white',
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
        <div className="border-b border-gray-300 dark:border-gray-700 last:border-b-0">
            <div
                className="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-gray-200/50 dark:hover:bg-gray-700/50 transition-colors"
                onClick={onToggle}
            >
                <div className="flex-1 text-sm text-gray-800 dark:text-gray-200 truncate">
                    {renderSummary(item)}
                </div>
                <span className="text-gray-600 dark:text-gray-400 ml-2 text-xs">
                    <Chevron direction={(isExpanded) ? 'up' : 'down'} className="w-3 h-3" />
                </span>
            </div>

            {isExpanded && (
                <div className="px-4 pb-4 bg-gray-100/50 dark:bg-gray-800/50 border-t border-gray-300 dark:border-gray-700">
                    <div className="pt-3 text-sm text-gray-700 dark:text-gray-300">
                        {renderDetail(item)}
                    </div>

                    {actions && (
                        <div className="flex gap-2 mt-3 pt-3 border-t border-gray-300 dark:border-gray-700">
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
