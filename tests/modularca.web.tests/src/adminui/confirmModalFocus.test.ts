import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The confirm dialog moves focus when it opens (to Cancel) and when it closes (back to the
 * opener). Its effect once depended on the caller's `onCancel`, so a caller that passes an
 * inline function re-ran it on every render. Schedules re-renders every second, and the
 * step-up dialog shown above a confirm dialog lost focus each time: a TOTP code could not be
 * typed into it.
 */
describe('the confirm dialog and focus', () => {
    const source = readFileSync(resolve(__dirname, '../../../../modularca.adminui/src/components/ConfirmModal.tsx'), 'utf8');

    it('moves focus when it opens and closes, and at no other time', () => {
        const effect = source.slice(source.indexOf('useEffect(() => {'));
        const deps = effect.slice(effect.indexOf('    }, ['), effect.indexOf(']);') + 3);
        expect(deps.trim()).toBe('}, [isOpen]);');
    });

    it('reads the caller’s cancel handler and its busy state through refs', () => {
        expect(source).toContain('onCancelRef.current = onCancel;');
        expect(source).toContain('loadingRef.current = loading;');
        expect(source).toContain("if (e.key === 'Escape' && !loadingRef.current) { e.stopPropagation(); onCancelRef.current(); }");
    });
});
