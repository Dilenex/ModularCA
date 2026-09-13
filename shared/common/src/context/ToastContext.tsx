/**
 * Toast provider and the module-level `globalToast` escape hatch the API client uses to surface
 * transport errors from outside React.
 *
 * Byte-identical in adminui and userui before this move.
 *
 * `showToast` now takes either a string or a structured {@link NoticeInput}, and the default
 * lifetime comes from the severity rather than being a flat five seconds. Both are additive: the
 * 238 existing `showToast(type, message)` calls pass a string and name no duration, so they keep
 * compiling and keep rendering the same way — what changes is that the ones reporting a failure
 * now wait to be dismissed instead of erasing themselves mid-sentence.
 */
import React, { createContext, useContext, useState, useCallback } from 'react';
import { Toast, toastViewportClass, type ToastType } from '../components/Toast';
import { autoDismissMs, type NoticeInput } from '../notifications/notice';
import { consumeReported } from '../notifications/reported';

interface ToastItem { id: string; type: ToastType; message: NoticeInput; duration: number; }
interface ToastContextValue {
    /**
     * @param type Severity, which also selects the default lifetime.
     * @param message A sentence, or a structured notice with a title, code and correlation id.
     * @param duration Milliseconds; 0 pins the toast open. Omit to take the severity's default —
     *                 an explicit value always wins, so a call site that wants a transient error
     *                 or a persistent success can still say so.
     */
    showToast: (type: ToastType, message: NoticeInput, duration?: number) => void;
}

const ToastContext = createContext<ToastContextValue>({ showToast: () => {} });
export const useToast = () => useContext(ToastContext);

// Global toast function for use outside React (e.g., API client)
let _globalShowToast: ToastContextValue['showToast'] = () => {};
export const setGlobalToast = (fn: typeof _globalShowToast) => { _globalShowToast = fn; };
export const globalToast = (type: ToastType, message: NoticeInput, duration?: number) =>
    _globalShowToast(type, message, duration);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [toasts, setToasts] = useState<ToastItem[]>([]);

    const dismiss = useCallback((id: string) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    }, []);

    const showToast = useCallback((type: ToastType, message: NoticeInput, duration?: number) => {
        // The API client toasts every failure it parses and then throws, and the call site that
        // catches it usually toasts `err.message` too — the same failure, flattened to one line.
        // A string that exactly matches one the client just reported is that echo; drop it and
        // leave the structured original standing. See notifications/reported.ts.
        if (typeof message === 'string' && consumeReported(message)) return;

        const id = crypto.randomUUID();
        // The timer belongs to the toast, which suspends it on hover and focus.
        setToasts(prev => [...prev, { id, type, message, duration: duration ?? autoDismissMs(type) }]);
    }, []);

    React.useEffect(() => { setGlobalToast(showToast); }, [showToast]);

    return (
        <ToastContext.Provider value={{ showToast }}>
            {children}
            <div className={toastViewportClass}>
                {toasts.map(t => <Toast key={t.id} {...t} onDismiss={dismiss} />)}
            </div>
        </ToastContext.Provider>
    );
};
