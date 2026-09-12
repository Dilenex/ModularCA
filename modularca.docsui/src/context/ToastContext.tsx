import React, { createContext, useContext, useState, useCallback } from 'react';
import { Toast, toastViewportClass, type ToastType } from '@shared/components/Toast';
import { autoDismissMs, type NoticeInput } from '@shared/notifications/notice';

interface ToastItem { id: string; type: ToastType; message: NoticeInput; }
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
        // Errors and warnings pin themselves open; see autoDismissMs.
        const lifetime = duration ?? autoDismissMs(type);
        setToasts(prev => [...prev, { id, type, message }]);
        if (lifetime > 0) setTimeout(() => dismiss(id), lifetime);
    }, [dismiss]);

    return (
        <ToastContext.Provider value={{ showToast }}>
            {children}
            <div className={toastViewportClass}>
                {toasts.map(t => <Toast key={t.id} {...t} onDismiss={dismiss} />)}
            </div>
        </ToastContext.Provider>
    );
};
