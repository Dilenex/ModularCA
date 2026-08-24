import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import ExpandableRow from './ExpandableRow';

interface Action {
    label: string;
    onClick: () => void | Promise<void>;
    variant?: 'default' | 'danger' | 'success';
    confirm?: string;
}

interface DataCardProps<T> {
    title: string;
    fetchData: () => Promise<T[]>;
    renderSummary: (item: T) => React.ReactNode;
    renderDetail: (item: T) => React.ReactNode;
    actions?: (item: T) => Action[];
    onViewAll?: () => void;
    maxItems?: number;
    emptyMessage?: string;
    keyExtractor: (item: T) => string;
    refreshTrigger?: number;
    /** "inline" = accordion expand (default), "modal" = popup card overlay */
    detailMode?: 'inline' | 'modal';
    /** Title shown in the modal header. Receives the selected item. */
    modalTitle?: (item: T) => string;
    /** URL for the "Go to full view" link in the modal header. Receives the selected item. */
    modalFullViewUrl?: (item: T) => string;
}

export default function DataCard<T>({
    title,
    fetchData,
    renderSummary,
    renderDetail,
    actions,
    onViewAll,
    maxItems = 5,
    emptyMessage = 'No items found',
    keyExtractor,
    refreshTrigger = 0,
    detailMode = 'inline',
    modalTitle,
    modalFullViewUrl,
}: DataCardProps<T>) {
    const navigate = useNavigate();
    const [items, setItems] = useState<T[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [expandedKey, setExpandedKey] = useState<string | null>(null);
    const [modalItem, setModalItem] = useState<T | null>(null);
    const [actionLoading, setActionLoading] = useState(false);
    // Two-click confirmation for the modal's action buttons, matching ExpandableRow. Without
    // it the modal ignored Action.confirm entirely, and since every DataCard in the app uses
    // detailMode="modal" the confirm path was dead everywhere — the Dashboard's "Revoke"
    // button revoked a certificate on a single click, with no prompt.
    const [confirmingAction, setConfirmingAction] = useState<string | null>(null);
    const [actionError, setActionError] = useState<string | null>(null);

    const reload = () => {
        setLoading(true);
        setError(null);
        fetchData()
            .then((data) => {
                setItems(Array.isArray(data) ? data.slice(0, maxItems) : []);
                setLoading(false);
            })
            .catch((err) => {
                setError(err.message || 'Failed to load');
                setLoading(false);
            });
    };

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);

        fetchData()
            .then((data) => {
                if (!cancelled) {
                    setItems(Array.isArray(data) ? data.slice(0, maxItems) : []);
                    setLoading(false);
                }
            })
            .catch((err) => {
                if (!cancelled) {
                    setError(err.message || 'Failed to load');
                    setLoading(false);
                }
            });

        return () => { cancelled = true; };
    }, [refreshTrigger]);

    const handleItemClick = (item: T, key: string) => {
        if (detailMode === 'modal') {
            setModalItem(item);
            setActionError(null);
        } else {
            setExpandedKey(expandedKey === key ? null : key);
        }
    };

    const handleModalAction = async (action: Action) => {
        if (action.confirm && confirmingAction !== action.label) {
            setConfirmingAction(action.label);
            setTimeout(() => setConfirmingAction(null), 3000);
            return;
        }
        setConfirmingAction(null);
        setActionLoading(true);
        setActionError(null);
        try {
            await action.onClick();
            setModalItem(null);
            reload();
        } catch (err: any) {
            setActionError(err.message || 'Action failed');
        } finally {
            setActionLoading(false);
        }
    };

    const variantClasses: Record<string, string> = {
        default: 'bg-gray-600 hover:bg-gray-400 dark:hover:bg-gray-500 text-gray-900 dark:text-white',
        danger: 'bg-red-700 hover:bg-red-600 text-gray-900 dark:text-white',
        success: 'bg-green-700 hover:bg-green-600 text-gray-900 dark:text-white',
    };

    return (
        <>
            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                {/* Header */}
                <div className="flex items-center justify-between px-4 py-3 border-b border-gray-300 dark:border-gray-700 bg-gray-100 dark:bg-gray-800">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{title}</h3>
                    {onViewAll && (
                        <button
                            onClick={onViewAll}
                            className="text-xs text-blue-800 dark:text-blue-400 hover:text-blue-300 transition-colors"
                        >
                            View All
                        </button>
                    )}
                </div>

                {/* Content */}
                <div className="max-h-80 overflow-y-auto">
                    {loading && (
                        <div className="p-4 text-sm text-gray-600 dark:text-gray-400 text-center">Loading...</div>
                    )}

                    {error && (
                        <div className="p-4 text-sm text-red-800 dark:text-red-400 text-center">{error}</div>
                    )}

                    {!loading && !error && items.length === 0 && (
                        <div className="p-4 text-sm text-gray-600 text-center">{emptyMessage}</div>
                    )}

                    {!loading && !error && items.map((item) => {
                        const key = keyExtractor(item);

                        if (detailMode === 'modal') {
                            return (
                                <div
                                    key={key}
                                    className="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-gray-200/50 dark:hover:bg-gray-700/50 transition-colors border-b border-gray-300 dark:border-gray-700 last:border-b-0"
                                    onClick={() => handleItemClick(item, key)}
                                >
                                    <div className="flex-1 text-sm text-gray-800 dark:text-gray-200 truncate">
                                        {renderSummary(item)}
                                    </div>
                                    <span className="text-gray-600 ml-2 text-xs">›</span>
                                </div>
                            );
                        }

                        return (
                            <ExpandableRow
                                key={key}
                                item={item}
                                isExpanded={expandedKey === key}
                                onToggle={() => handleItemClick(item, key)}
                                renderSummary={renderSummary}
                                renderDetail={renderDetail}
                                actions={actions}
                            />
                        );
                    })}
                </div>
            </div>

            {/* Modal overlay for detail view */}
            {detailMode === 'modal' && modalItem && (
                <div
                    className="fixed inset-0 bg-black/25 dark:bg-black/60 flex items-center justify-center z-50"
                    onClick={() => { if (!actionLoading) { setConfirmingAction(null); setModalItem(null); } }}
                >
                    <div
                        className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-2xl w-full max-w-lg mx-4 max-h-[80vh] overflow-y-auto"
                        onClick={(e) => e.stopPropagation()}
                    >
                        {/* Modal header */}
                        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-300 dark:border-gray-700">
                            <h3 className="text-sm font-semibold text-gray-900 dark:text-white truncate">
                                {modalTitle ? modalTitle(modalItem) : title}
                            </h3>
                            <div className="flex items-center gap-3 flex-shrink-0">
                                {modalFullViewUrl && (
                                    <button
                                        onClick={() => { setModalItem(null); navigate(modalFullViewUrl(modalItem)); }}
                                        className="text-xs text-blue-800 dark:text-blue-400 hover:text-blue-300 transition-colors whitespace-nowrap"
                                    >
                                        Go to full view →
                                    </button>
                                )}
                                <button
                                    onClick={() => { if (!actionLoading) { setConfirmingAction(null); setModalItem(null); } }}
                                    className="text-gray-600 hover:text-gray-900 dark:hover:text-white text-lg transition-colors"
                                >
                                    ✕
                                </button>
                            </div>
                        </div>

                        {/* Modal body */}
                        <div className="px-5 py-4 text-sm text-gray-700 dark:text-gray-300">
                            {renderDetail(modalItem)}
                        </div>

                        {/* Modal actions */}
                        {actions && (
                            <div className="px-5 py-4 border-t border-gray-300 dark:border-gray-700 space-y-3">
                                {actionError && (
                                    <div className="text-xs text-red-800 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-800 rounded px-3 py-2">
                                        {actionError}
                                    </div>
                                )}
                                {/* The confirm string is a warning written for the operator; show
                                    it rather than relying on the button label alone. */}
                                {confirmingAction && (() => {
                                    const pending = actions?.(modalItem)?.find((a) => a.label === confirmingAction);
                                    return pending?.confirm ? (
                                        <div className="text-xs text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-800 rounded px-3 py-2">
                                            {pending.confirm} — click again to continue.
                                        </div>
                                    ) : null;
                                })()}
                                <div className="flex gap-2 justify-end">
                                    <button
                                        onClick={() => { if (!actionLoading) { setConfirmingAction(null); setModalItem(null); } }}
                                        className="px-4 py-2 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
                                        disabled={actionLoading}
                                    >
                                        Close
                                    </button>
                                    {actions(modalItem).map((action) => (
                                        <button
                                            key={action.label}
                                            onClick={() => handleModalAction(action)}
                                            disabled={actionLoading}
                                            className={`px-4 py-2 text-xs rounded transition-colors disabled:opacity-50 ${variantClasses[action.variant || 'default']}`}
                                        >
                                            {actionLoading ? 'Working...' : (confirmingAction === action.label ? `Confirm ${action.label}?` : action.label)}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </>
    );
}
