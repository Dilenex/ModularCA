import React, { createContext, useContext, useState, useCallback } from 'react';
import { Toast, type ToastType } from '@shared/components/Toast';

interface ToastItem { id: string; type: ToastType; message: string; }
interface ToastContextValue { showToast: (type: ToastType, message: string, duration?: number) => void; }

/**
 * Toast ids are React list keys with a page lifetime -- they need to be unique, not
 * unguessable. This used to call `crypto.randomUUID()`, which is [SecureContext]-gated and
 * therefore UNDEFINED on a non-localhost http:// origin. This portal is deliberately reachable
 * over plain HTTP (HttpSchemeEnforcementMiddleware allow-lists /public and
 * /api/v1/public/info, because a relying party fetching the CA certificate may not have TLS
 * trust established yet), so every toast threw a TypeError on exactly the deployment the
 * portal exists to serve -- including the toast that would have reported the original error.
 */
let toastSequence = 0;
const nextToastId = () => `toast-${++toastSequence}`;

const ToastContext = createContext<ToastContextValue>({ showToast: () => {} });
export const useToast = () => useContext(ToastContext);

// Mirror the admin client's globalToast pattern so api/client.ts
// can surface backend errors as toasts without a hook context.
let _globalShowToast: ToastContextValue['showToast'] = () => { };
export const setGlobalToast = (fn: typeof _globalShowToast) => { _globalShowToast = fn; };
export const globalToast = (type: ToastType, message: string) => _globalShowToast(type, message);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [toasts, setToasts] = useState<ToastItem[]>([]);

    const dismiss = useCallback((id: string) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    }, []);

    const showToast = useCallback((type: ToastType, message: string, duration = 5000) => {
        const id = nextToastId();
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
