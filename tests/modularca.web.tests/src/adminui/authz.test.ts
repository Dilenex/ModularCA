import { describe, expect, it } from 'vitest';
import { Capabilities } from '@shared/generated';
import { can, canAnywhere, canAtSpace, canInSpace, canSpaceWide, canUseAdminConsole, consoleCas, instanceCas, NO_CAPABILITIES, spacesOf, type EffectiveCapabilities } from '@adminui/authz';
import { CA_AUDIT, CA_MANAGE, CA_MANAGE_SPACE, GROUP_MANAGE, SYSTEM_OPERATOR } from '@adminui/gates';
import { gateAllows } from '@adminui/scope';

/**
 * The capability checks the console gates on, over the `capabilities` payload of
 * `GET /api/v1/me`. The server folds the four grant sources into system-scoped and per-CA
 * sets; these pin how the client reads them, including the two decisions that matter most: a
 * system-scoped capability counts on every CA, and a Requester (the self-service pair only)
 * never reaches the console.
 */
const caA = { id: 'a', label: 'ca-a', name: 'A', isSshCa: false, spaceId: 't1', spaceName: 'Space One', spaceSlug: 'one', capabilities: [Capabilities.CertView, Capabilities.CertRevoke] };
const caB = { id: 'b', label: 'ca-b', name: 'B', isSshCa: true, spaceId: 't2', spaceName: 'Space Two', spaceSlug: 'two', capabilities: [Capabilities.CertView] };

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

    it('does not count a space-wide grant over a space with no CA, as the CA-scoped list endpoints do not', () => {
        const emptySpaceAdmin: EffectiveCapabilities = {
            system: [Capabilities.CertView],
            cas: [],
            spaces: [{ id: 't9', name: 'Empty', slug: 'empty', capabilities: [Capabilities.CaManage, Capabilities.GroupManage] }],
        };
        expect(canAnywhere(emptySpaceAdmin, Capabilities.CaManage)).toBe(false);
        expect(canAnywhere(emptySpaceAdmin, Capabilities.GroupManage)).toBe(false);
        expect(canAnywhere(emptySpaceAdmin, Capabilities.CertView)).toBe(true);
        expect(canSpaceWide(emptySpaceAdmin, Capabilities.CaManage)).toBe(true);
        expect(canSpaceWide(emptySpaceAdmin, Capabilities.SystemManage)).toBe(false);
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

describe('spaces', () => {
    it('lists the spaces of administrable CAs once each, and checks a capability within one', () => {
        const twoSpaces: EffectiveCapabilities = { system: [], cas: [caA, { ...caB, capabilities: [Capabilities.CaManage] }, { ...caA, id: 'a2', label: 'ca-a2' }] };
        expect(spacesOf(twoSpaces)).toEqual([{ id: 't1', name: 'Space One', slug: 'one' }, { id: 't2', name: 'Space Two', slug: 'two' }]);
        expect(spacesOf(operatorOnA)).toEqual([{ id: 't1', name: 'Space One', slug: 'one' }]); // ca-b is requester-only there
        expect(canInSpace(operatorOnA, Capabilities.CertRevoke, 't1')).toBe(true);
        expect(canInSpace(operatorOnA, Capabilities.CertRevoke, 't2')).toBe(false);
        expect(canInSpace(null, Capabilities.CertRevoke, 't1')).toBe(false);
    });
});

describe('canAtSpace', () => {
    const spaceAdmin: EffectiveCapabilities = {
        system: [],
        cas: [{ ...caA, capabilities: [Capabilities.CaManage] }],
        spaces: [{ id: 't3', name: 'Space Three', slug: 'three', capabilities: [Capabilities.CaManage] }],
    };

    it('is true only for a space-wide or system-scoped holder', () => {
        expect(canAtSpace(spaceAdmin, Capabilities.CaManage, 't3')).toBe(true);
        expect(canAtSpace(spaceAdmin, Capabilities.CaManage, 't1')).toBe(false); // held on ca-a only
        expect(canAtSpace(spaceAdmin, Capabilities.SystemManage, 't3')).toBe(false);
        expect(canAtSpace({ system: [Capabilities.CaManage], cas: [] }, Capabilities.CaManage, 'any')).toBe(true);
        expect(canAtSpace(null, Capabilities.CaManage, 't3')).toBe(false);
    });

    it('lists a space administered space-wide even before it has a CA', () => {
        expect(spacesOf(spaceAdmin).map(t => t.id)).toEqual(['t1', 't3']);
        const requesterOnly: EffectiveCapabilities = { system: [], cas: [], spaces: [{ id: 't4', name: 'Four', slug: 'four', capabilities: [Capabilities.CertRequest] }] };
        expect(spacesOf(requesterOnly)).toEqual([]);
    });

    it('lets a space administrator with no CA yet into the console and the space scope', () => {
        const noCaYet: EffectiveCapabilities = { system: [], cas: [], spaces: [{ id: 't3', name: 'Space Three', slug: 'three', capabilities: [Capabilities.CaManage] }] };
        expect(canUseAdminConsole(noCaYet)).toBe(true);
        expect(canInSpace(noCaYet, Capabilities.CaManage, 't3')).toBe(true);
        expect(canInSpace(noCaYet, Capabilities.CaManage, 't1')).toBe(false);
        const requesterOnly: EffectiveCapabilities = { system: [], cas: [], spaces: [{ id: 't4', name: 'Four', slug: 'four', capabilities: [Capabilities.CertRequest, Capabilities.CertView] }] };
        expect(canUseAdminConsole(requesterOnly)).toBe(false);
    });
});

describe('instance CAs (no space)', () => {
    const signing = { id: 'sys', label: 'system-signing-ca', name: 'System Signing CA', isSshCa: false, spaceId: null, spaceName: '', spaceSlug: '', capabilities: [Capabilities.AuditView] };
    const auditor: EffectiveCapabilities = { system: [Capabilities.AuditView], cas: [signing, caA] };

    it('are not a space', () => {
        expect(spacesOf(auditor)).toEqual([{ id: 't1', name: 'Space One', slug: 'one' }]);
        expect(spacesOf({ system: [], cas: [signing] })).toEqual([]);
    });

    it('are listed apart and still checked per CA', () => {
        expect(instanceCas(auditor).map(c => c.id)).toEqual(['sys']);
        expect(can(auditor, Capabilities.AuditView, 'sys')).toBe(true);
        expect(canInSpace(auditor, Capabilities.CertView, 't1')).toBe(true);
    });
});

/**
 * Page gates match what the server answers the page's calls. The CA-scoped list endpoints need
 * the capability on at least one CA, so a space administrator whose space has no CA yet sees only
 * the pages that work without one (Authorities, to create it, and Ceremonies), and a
 * system-operator page is not offered to a CA administrator.
 */
describe('page gates', () => {
    const emptySpace = { kind: 'space' as const, spaceId: 't9', slug: 'empty', name: 'Empty' };
    const emptySpaceAdmin: EffectiveCapabilities = {
        system: [],
        cas: [],
        spaces: [{ id: 't9', name: 'Empty', slug: 'empty', capabilities: [Capabilities.CaManage, Capabilities.GroupManage, Capabilities.CertView] }],
    };

    it('offers a space administrator with no CA yet only the pages that work without one', () => {
        expect(gateAllows(emptySpaceAdmin, CA_MANAGE_SPACE, emptySpace)).toBe(true);
        expect(gateAllows(emptySpaceAdmin, CA_MANAGE, emptySpace)).toBe(false);
        expect(gateAllows(emptySpaceAdmin, GROUP_MANAGE, emptySpace)).toBe(false);
        expect(gateAllows(emptySpaceAdmin, CA_AUDIT, emptySpace)).toBe(false);
        expect(gateAllows(emptySpaceAdmin, CA_MANAGE_SPACE, { kind: 'all' })).toBe(true);
        expect(gateAllows(emptySpaceAdmin, GROUP_MANAGE, { kind: 'all' })).toBe(false);
    });

    it('offers the same pages once the space has a CA', () => {
        const withCa: EffectiveCapabilities = {
            ...emptySpaceAdmin,
            cas: [{ ...caA, id: 'c9', spaceId: 't9', spaceSlug: 'empty', capabilities: [Capabilities.CaManage, Capabilities.GroupManage, Capabilities.CertView] }],
        };
        expect(gateAllows(withCa, CA_MANAGE, emptySpace)).toBe(true);
        expect(gateAllows(withCa, GROUP_MANAGE, emptySpace)).toBe(true);
        expect(gateAllows(withCa, GROUP_MANAGE, { kind: 'all' })).toBe(true);
    });

    it('keeps a system-operator page to system-scoped ca.manage', () => {
        const caAdmin: EffectiveCapabilities = { system: [], cas: [{ ...caA, capabilities: [Capabilities.CaManage] }] };
        expect(gateAllows(caAdmin, SYSTEM_OPERATOR, { kind: 'all' })).toBe(false);
        expect(gateAllows({ system: [Capabilities.CaManage], cas: [] }, SYSTEM_OPERATOR, { kind: 'all' })).toBe(true);
    });
});
