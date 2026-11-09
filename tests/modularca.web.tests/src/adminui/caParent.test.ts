import { describe, expect, it } from 'vitest';
import { candidateSetKey, reconcileParent } from '@adminui/pages/caParent';

// Bug hunt 2026-11, F7: after a scope switch to a subtree with the same number of CAs, the
// create-CA form kept the old parent's id while showing the new scope's first CA.
describe('the parent CA the create form holds', () => {
    it('keeps the current parent while it is still a candidate', () => {
        expect(reconcileParent(['a1', 'a2'], 'a2')).toBe('a2');
    });

    it('takes the first candidate when the current parent left the scope', () => {
        expect(reconcileParent(['b1', 'b2'], 'a1')).toBe('b1');
    });

    it('holds none when nothing may be a parent', () => {
        expect(reconcileParent([], 'a1')).toBe('');
    });

    it('notices a switch between scopes of the same size', () => {
        expect(candidateSetKey(['a1', 'a2'])).not.toBe(candidateSetKey(['b1', 'b2']));
        expect(candidateSetKey(['a1', 'a2'])).toBe(candidateSetKey(['a1', 'a2']));
    });
});
