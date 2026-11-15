import { describe, expect, it } from 'vitest';
import { cryptoperiodRows } from '@adminui/pages/caLifecycle';
import { parentCaDisplay } from '@adminui/pages/caParentDisplay';
import { isRootCa } from '@adminui/pages/caRenewal';

const rootId = 'c862cb48-e273-4b4f-8f85-9150c1d719e0';
const root = { id: rootId, name: 'Example Root CA', label: 'example-root', isRoot: true, parentCaId: null };
const child = { id: 'child', name: 'Issuing CA', label: 'issuing', isRoot: false, parentCaId: rootId };
/** The same CA as the server sends it to a viewer whose space fence does not admit the parent. */
const fencedChild = { id: 'child', name: 'Issuing CA', label: 'issuing', isRoot: false, parentCaId: null, parentHidden: true };

/** The "Parent CA" row of a CA's page names the parent and links to it; it never shows an id. */
describe('the parent of a CA on its page', () => {
    it('is the parent\'s name as a link to its page, with its label beside it', () => {
        expect(parentCaDisplay(child, [root, child])).toEqual({ kind: 'link', name: 'Example Root CA', label: 'example-root', to: `/authorities/manage/${rootId}` });
    });

    it('does not repeat a label that is the name, and falls back to the label for a parent with no name', () => {
        expect(parentCaDisplay(child, [{ ...root, label: 'Example Root CA' }])).toMatchObject({ kind: 'link', label: null });
        expect(parentCaDisplay(child, [{ ...root, name: '' }])).toMatchObject({ kind: 'link', name: 'example-root', label: null });
    });

    it('says a root has none', () => {
        expect(parentCaDisplay(root, [root, child])).toEqual({ kind: 'root', text: 'None (root)' });
    });

    it('says "Not visible to you" when the server gives no parent identity', () => {
        expect(parentCaDisplay(fencedChild, [fencedChild])).toEqual({ kind: 'hidden', text: 'Not visible to you' });
        // Not a root, though it carries no parent id.
        expect(parentCaDisplay(fencedChild, [fencedChild])).not.toMatchObject({ kind: 'root' });
    });

    it('never takes a parent\'s name from the lifetime facts, whatever they carry', () => {
        // The server sends no parentName for a hidden parent. A stale or older answer that did
        // must still not put the name on the page.
        const leaky = { ...fencedChild, cryptoperiod: { parentName: 'Example Root CA' } };
        expect(parentCaDisplay(leaky, [leaky])).toEqual({ kind: 'hidden', text: 'Not visible to you' });
        const leakyWithId = { ...child, cryptoperiod: { parentName: 'Example Root CA' } };
        expect(parentCaDisplay(leakyWithId, [leakyWithId])).toEqual({ kind: 'hidden', text: 'Not visible to you' });
        expect(JSON.stringify(parentCaDisplay(leakyWithId, [leakyWithId]))).not.toContain('Example Root CA');
    });

    it('says a parent the list does not hold is not visible, and never shows its id', () => {
        const shown = parentCaDisplay(child, [child]);
        expect(shown).toEqual({ kind: 'hidden', text: 'Not visible to you' });
        for (const viewers of [[root, child], [child], []]) expect(JSON.stringify({ ...parentCaDisplay(child, viewers), to: undefined })).not.toContain(rootId);
    });

    it('shows nothing for a CA that is neither a root nor has a parent recorded', () => {
        expect(parentCaDisplay({ id: 'x', isRoot: false, parentCaId: null }, [])).toBeNull();
        expect(parentCaDisplay({ id: 'x', isRoot: false, parentCaId: null, parentHidden: false }, [])).toBeNull();
        expect(parentCaDisplay(null, [])).toBeNull();
    });
});

/** What else on the CA's page reads the parent: the renewal form and the lifetime facts. */
describe('a CA whose parent is hidden from the viewer', () => {
    it('is not taken for a root by the renewal form', () => {
        expect(isRootCa(fencedChild)).toBe(false);
        expect(isRootCa(child)).toBe(false);
        expect(isRootCa(root)).toBe(true);
    });

    it('has no "Parent\'s certificate expires" row: the server sends neither its name nor its date', () => {
        const period = { certificateNotAfter: '2035-01-01T00:00:00Z', parentName: null, parentCertificateNotAfter: null };
        expect(cryptoperiodRows(period).some((row) => row.label.startsWith('Parent'))).toBe(false);
        const open = cryptoperiodRows({ ...period, parentName: 'Example Root CA', parentCertificateNotAfter: '2030-01-01T00:00:00Z' });
        expect(open.find((row) => row.label === "Parent's certificate expires")?.value).toContain('Example Root CA');
    });
});
