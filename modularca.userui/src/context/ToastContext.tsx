import React, { createContext, useContext, useState, useCallback } from 'react';
import { Toast, type ToastType } from '@shared/components/Toast';

interface ToastItem { id: string; type: ToastType; message: string; }
interface ToastContextValue { showToast: (type: ToastType, message: string, duration?: number) => void; }

const ToastContext = createContext<ToastContextValue>({ showToast: () => {} });
export const useToast = () => useContext(ToastContext);

// Global toast function for use outside React (e.g., API client)
let _globalShowToast: ToastContextValue['showToast'] = () => {};
export const setGlobalToast = (fn: typeof _globalShowToast) => { _globalShowToast = fn; };
export const globalToast = (type: ToastType, message: string) => _globalShowToast(type, message);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [toasts, setToasts] = useState<ToastItem[]>([]);

    const dismiss = useCallback((id: string) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    }, []);

    const showToast = useCallback((type: ToastType, message: string, duration = 5000) => {
        const id = crypto.randomUUID();
        setToasts(prev => [...prev, { id, type, message }]);
        if (duration > 0) setTimeout(() => dismiss(id), duration);
    }, [dismiss]);

    React.useEffect(() => { setGlobalToast(showToast); }, [showToast]);

    return (
        <ToastContext.Provider value={{ showToast }}>
            {children}
            <div className="fixed top-4 right-4 z-[100] flex flex-col gap-2 max-w-sm">
                {toasts.map(t => <Toast key={t.id} {...t} onDismiss={dismiss} />)}
            </div>
        </ToastContext.Provider>
    );
};
