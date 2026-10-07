import { describe, expect, it } from 'vitest';
import { ocspRows, ocspStatus } from '@adminui/pages/ocspReadiness';

describe('the badge a CA\'s OCSP state gets', () => {
    it('says Answering for a usable responder, whatever else the feed sends', () => {
        expect(ocspStatus({ mode: 'delegated', problem: null })).toEqual({ status: 'active', label: 'Answering' });
    });

    it('says Refusing when there is a problem, in any mode', () => {
        expect(ocspStatus({ mode: 'delegated', problem: 'revoked' })?.label).toBe('Refusing');
        expect(ocspStatus({ mode: 'none', problem: 'This CA has no OCSP responder certificate.' })?.label).toBe('Refusing');
    });

    it('tells direct signing and switched-off apart from a working responder', () => {
        expect(ocspStatus({ mode: 'direct', problem: null })?.label).toBe('CA key signs');
        expect(ocspStatus({ mode: 'off', problem: null })).toEqual({ status: 'disabled', label: 'Not served' });
    });

    it('is null when the feed reports nothing', () => {
        expect(ocspStatus(null)).toBeNull();
        expect(ocspStatus(undefined)).toBeNull();
    });
});

describe('which CAs the OCSP card lists', () => {
    const hierarchy = [
        {
            id: 'root', name: 'Root', ocspResponder: { mode: 'delegated', problem: null },
            children: [
                { id: 'sub', name: 'Sub', ocspResponder: { mode: 'delegated', problem: 'The responder certificate does not carry the OCSP signing extended key usage.' }, children: [] },
            ],
        },
        { id: 'direct', name: 'Direct', ocspResponder: { mode: 'direct', problem: null } },
        { id: 'off', name: 'Off', ocspResponder: { mode: 'off', problem: null } },
        { id: 'disabled', name: 'Disabled', ocspResponder: null },
    ];

    it('walks children, and leaves out a CA that serves no OCSP', () => {
        expect(ocspRows(hierarchy).map((r) => r.id).sort()).toEqual(['direct', 'root', 'sub']);
    });

    it('puts a refusing CA first', () => {
        const rows = ocspRows(hierarchy);
        expect(rows[0].id).toBe('sub');
        expect(rows[0].problem).toContain('OCSP signing');
        expect(rows.slice(1).every((r) => r.problem === null)).toBe(true);
    });

    it('is empty for an empty or missing feed', () => {
        expect(ocspRows([])).toEqual([]);
        expect(ocspRows(undefined as any)).toEqual([]);
    });
});
