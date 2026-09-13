import React, { createContext, useContext, useState, useCallback } from 'react';
import { Toast, toastViewportClass, type ToastType } from '@shared/components/Toast';
import { autoDismissMs, type NoticeInput } from '@shared/notifications/notice';

interface ToastItem { id: string; type: ToastType; message: NoticeInput; duration: number; }
/** `message` also accepts a structured notice; `duration` defaults to the severity's lifetime. */
interface ToastContextValue { showToast: (type: ToastType, message: NoticeInput, duration?: number) => void; }

const ToastContext = createContext<ToastContextValue>({ showToast: () => {} });
export const useToast = () => useContext(ToastContext);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [toasts, setToasts] = useState<ToastItem[]>([]);

    const dismiss = useCallback((id: string) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    }, []);

    const showToast = useCallback((type: ToastType, message: NoticeInput, duration?: number) => {
        const id = crypto.randomUUID();
        // The timer belongs to the toast, which suspends it on hover and focus; see autoDismissMs
        // for the lifetimes and why errors are long rather than pinned.
        setToasts(prev => [...prev, { id, type, message, duration: duration ?? autoDismissMs(type) }]);
    }, []);

    return (
        <ToastContext.Provider value={{ showToast }}>
            {children}
            <div className={toastViewportClass}>
                {toasts.map(t => <Toast key={t.id} {...t} onDismiss={dismiss} />)}
            </div>
        </ToastContext.Provider>
    );
};
