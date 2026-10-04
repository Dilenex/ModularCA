import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

/**
 * Scrolls to the element the URL's hash names once `ready` (the section has rendered). The
 * router does not do this itself, and a section that renders after a fetch would be missed by
 * the browser's own jump.
 */
export function useScrollToHash(ready: boolean): void {
    const { hash } = useLocation();
    useEffect(() => {
        if (!ready || hash.length < 2) return;
        document.getElementById(decodeURIComponent(hash.slice(1)))?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, [ready, hash]);
}
