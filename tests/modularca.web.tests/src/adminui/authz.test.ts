import { describe, expect, it } from 'vitest';
import { Capabilities } from '@shared/generated';
import { can, canAnywhere, canInTenant, canUseAdminConsole, consoleCas, NO_CAPABILITIES, tenantsOf, type EffectiveCapabilities } from '@adminui/authz';

/**
 * The capability checks the console gates on, over the `capabilities` payload of
 * `GET /api/v1/me`. The server folds the four grant sources into system-scoped and per-CA
 * sets; these pin how the client reads them, including the two decisions that matter most: a
 * system-scoped capability counts on every CA, and a Requester (the self-service pair only)
 * never reaches the console.
 */
const caA = { id: 'a', label: 'ca-a', name: 'A', isSshCa: false, tenantId: 't1', tenantName: 'Tenant One', tenantSlug: 'one', capabilities: [Capabilities.CertView, Capabilities.CertRevoke] };
const caB = { id: 'b', label: 'ca-b', name: 'B', isSshCa: true, tenantId: 't2', tenantName: 'Tenant Two', tenantSlug: 'two', capabilities: [Capabilities.CertView] };

const operatorOnA: EffectiveCapabilities = { system: [], cas: [caA, caB] };
const systemAuditor: EffectiveCapabilities = {
    system: [Capabilities.AuditView],
    cas: [{ ...caA, capabilities: [Capabilities.AuditView] }],
};

describe('can', () => {
    it('checks the named CA', () => {
        expect(can(operatorOnA, Capabilities.CertRevoke, 'a')).toBe(true);
        expect(can(operatorOnA, Capabilities.CertRevoke, 'b')).toBe(false);
        expect(can(operatorOnA, Capabilities.CertRevoke, 'nope')).toBe(false);
    });

    it('checks system scope when no CA is named', () => {
        expect(can(operatorOnA, Capabilities.CertRevoke)).toBe(false);
        expect(can(systemAuditor, Capabilities.AuditView)).toBe(true);
        expect(can(systemAuditor, Capabilities.AuditView, null)).toBe(true);
    });

    it('is false before /me has answered', () => {
        expect(can(null, Capabilities.CertView)).toBe(false);
        expect(can(NO_CAPABILITIES, Capabilities.CertView, 'a')).toBe(false);
    });
});

describe('canAnywhere', () => {
    it('is true for a capability held on any CA or at system scope', () => {
        expect(canAnywhere(operatorOnA, Capabilities.CertRevoke)).toBe(true);
        expect(canAnywhere(operatorOnA, Capabilities.SystemManage)).toBe(false);
        expect(canAnywhere(systemAuditor, Capabilities.AuditView)).toBe(true);
        expect(canAnywhere(undefined, Capabilities.AuditView)).toBe(false);
    });
});

describe('canUseAdminConsole', () => {
    it('is false for the self-service pair alone, anywhere', () => {
        const requester: EffectiveCapabilities = {
            system: [],
            cas: [{ ...caA, capabilities: [Capabilities.CertRequest, Capabilities.CertView] }],
        };
        expect(canUseAdminConsole(requester)).toBe(false);
        expect(canUseAdminConsole({ system: [Capabilities.CertView], cas: [] })).toBe(false);
        expect(canUseAdminConsole(null)).toBe(false);
    });

    it('is true for anything beyond that pair, at either scope', () => {
        expect(canUseAdminConsole(operatorOnA)).toBe(true);
        expect(canUseAdminConsole({ system: [Capabilities.AuditView], cas: [] })).toBe(true);
    });
});

describe('consoleCas', () => {
    it('lists only CAs with a console capability, keeping the server order', () => {
        expect(consoleCas(operatorOnA).map(c => c.id)).toEqual(['a']);
        expect(consoleCas(systemAuditor).map(c => c.id)).toEqual(['a']);
        expect(consoleCas(null)).toEqual([]);
    });
});

describe('tenants', () => {
    it('lists the tenants of administrable CAs once each, and checks a capability within one', () => {
        const twoTenants: EffectiveCapabilities = { system: [], cas: [caA, { ...caB, capabilities: [Capabilities.CaManage] }, { ...caA, id: 'a2', label: 'ca-a2' }] };
        expect(tenantsOf(twoTenants)).toEqual([{ id: 't1', name: 'Tenant One', slug: 'one' }, { id: 't2', name: 'Tenant Two', slug: 'two' }]);
        expect(tenantsOf(operatorOnA)).toEqual([{ id: 't1', name: 'Tenant One', slug: 'one' }]); // ca-b is requester-only there
        expect(canInTenant(operatorOnA, Capabilities.CertRevoke, 't1')).toBe(true);
        expect(canInTenant(operatorOnA, Capabilities.CertRevoke, 't2')).toBe(false);
        expect(canInTenant(null, Capabilities.CertRevoke, 't1')).toBe(false);
    });
});
