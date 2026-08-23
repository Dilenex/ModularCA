import React from 'react';

/**
 * Shared because the four copies had already begun to diverge: two spelled the status icons as
 * literal glyphs and two as escapes. That difference was harmless, but it is the same drift
 * that turned api/client.ts into four incompatible clients, and the styles here encode the
 * dark-mode contrast convention that every SPA is supposed to follow.
 */

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface ToastProps {
    id: string;
    type: ToastType;
    message: string;
    onDismiss: (id: string) => void;
}

const typeStyles: Record<ToastType, string> = {
    success: 'bg-green-50 dark:bg-green-900 border-green-500 text-green-800 dark:text-green-300',
    error: 'bg-red-50 dark:bg-red-900 border-red-500 text-red-800 dark:text-red-300',
    warning: 'bg-amber-50 dark:bg-amber-900 border-amber-500 text-amber-800 dark:text-amber-300',
    info: 'bg-blue-50 dark:bg-blue-900 border-blue-500 text-blue-800 dark:text-blue-300',
};

const typeIcons: Record<ToastType, string> = {
    success: '\u2713',
    error: '\u2715',
    warning: '\u26A0',
    info: '\u2139',
};

export const Toast: React.FC<ToastProps> = ({ id, type, message, onDismiss }) => (
    <div className={`flex items-start gap-3 px-4 py-3 rounded-lg border-l-4 shadow-lg animate-slide-in ${typeStyles[type]}`}>
        <span className="text-lg font-bold flex-shrink-0">{typeIcons[type]}</span>
        <p className="text-sm flex-1">{message}</p>
        <button onClick={() => onDismiss(id)} className="text-current opacity-50 hover:opacity-100 flex-shrink-0">&times;</button>
    </div>
);
