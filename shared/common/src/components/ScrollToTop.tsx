import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

/**
 * Resets scroll position and focus on every route change.
 *
 * Shared because it is a router-level accessibility behaviour, not a per-app decision: four
 * SPAs each mounted a byte-identical copy, so a fix to the focus reset would silently apply to
 * whichever one the author happened to be editing. setupui does not use it — it is a single
 * linear wizard with no route changes to reset.
 */

export const ScrollToTop: React.FC = () => {
    const { pathname } = useLocation();
    useEffect(() => {
        const main = document.querySelector('main');
        if (main) main.scrollTop = 0;
        window.scrollTo(0, 0);
        // Reset tab order: blur whatever held focus on the previous page so the
        // next Tab keystroke starts from the first focusable element on the new route.
        (document.activeElement as HTMLElement | null)?.blur();
    }, [pathname]);
    return null;
};
