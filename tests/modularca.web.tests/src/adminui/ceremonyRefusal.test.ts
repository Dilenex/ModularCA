import { describe, expect, it } from 'vitest';
import { ApiError, parseProblem } from '@shared-auth/api/problem';
import {
    CEREMONY_NO_APPROVER, CEREMONY_QUORUM_UNREACHABLE, INSTANCE_CEREMONY_SETTINGS_PATH, USERS_PATH,
    ceremonyRefusalAdvice, ceremonyRefusalLinks, readCeremonyRefusal, requirementWarning, spaceCeremonySettingsPath, stuckCeremonyNotice,
    type CeremonyRefusal,
} from '@adminui/pages/ceremonyRefusal';

const SPACE = '6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60';

/** The 409 body the server sends, as the API client would throw it. */
function refusalError(body: Record<string, unknown>, status = 409): ApiError {
    return new ApiError(parseProblem(status, JSON.stringify({
        type: 'https://tools.ietf.org/html/rfc7231#section-6.5.8',
        title: 'This ceremony could never be approved',
        status,
        detail: 'You’re the only administrator who can approve this, so the ceremony could never be completed. Nothing was started.',
        code: CEREMONY_NO_APPROVER,
        operationType: 'CreateIntermediateCA',
        requiredApprovals: 1,
        eligibleApprovers: 0,
        requirementScope: 'space',
        spaceId: SPACE,
        spaceName: 'Acme',
        canDisableRequirement: true,
        ...body,
    })));
}

const SUPER = { isSystemAdmin: true, canManageUsers: true };
const OPERATOR = { isSystemAdmin: false, canManageUsers: false };

describe('reading a ceremony refusal', () => {
    it('reads the 409 the server sends when nobody else can approve', () => {
        const refusal = readCeremonyRefusal(refusalError({}));
        expect(refusal).toEqual<CeremonyRefusal>({
            code: 'MCA-CFG-020',
            detail: 'You’re the only administrator who can approve this, so the ceremony could never be completed. Nothing was started.',
            requiredApprovals: 1,
            eligibleApprovers: 0,
            requirementScope: 'space',
            spaceId: SPACE,
            spaceName: 'Acme',
            canDisableRequirement: true,
        });
    });

    it('reads the too-few case with both numbers', () => {
        const refusal = readCeremonyRefusal(refusalError({
            code: CEREMONY_QUORUM_UNREACHABLE, requiredApprovals: 3, eligibleApprovers: 1,
            requirementScope: 'instance', spaceId: null, spaceName: null, canDisableRequirement: false,
            detail: 'This needs 3 approvals and only 1 other administrator can approve. Nothing was started.',
        }));
        expect(refusal?.code).toBe('MCA-CFG-021');
        expect(refusal?.requiredApprovals).toBe(3);
        expect(refusal?.eligibleApprovers).toBe(1);
        expect(refusal?.requirementScope).toBe('instance');
        expect(refusal?.spaceId).toBeNull();
        expect(refusal?.canDisableRequirement).toBe(false);
    });

    it('is null for any other failure', () => {
        expect(readCeremonyRefusal(refusalError({ code: 'MCA-RES-003' }))).toBeNull();
        expect(readCeremonyRefusal(refusalError({}, 400))).toBeNull();
        expect(readCeremonyRefusal(new Error('Step-up MFA cancelled'))).toBeNull();
        expect(readCeremonyRefusal(null)).toBeNull();
        expect(readCeremonyRefusal('409')).toBeNull();
    });

    it('offers no switch the response cannot name', () => {
        const noScope = readCeremonyRefusal(refusalError({ requirementScope: null, spaceId: null, canDisableRequirement: true }));
        expect(noScope?.requirementScope).toBeNull();
        expect(noScope?.canDisableRequirement).toBe(false);

        const unnamedSpace = readCeremonyRefusal(refusalError({ spaceId: null }));
        expect(unnamedSpace?.requirementScope).toBeNull();
        expect(ceremonyRefusalLinks(unnamedSpace!, SUPER).map((l) => l.key)).toEqual(['add-administrator']);
    });
});

describe('the next steps a refusal offers', () => {
    it('link a super to the space switch and to Users', () => {
        const refusal = readCeremonyRefusal(refusalError({}))!;
        expect(ceremonyRefusalLinks(refusal, SUPER)).toEqual([
            { key: 'space-switch', label: 'Key ceremony settings for space Acme', to: `/spaces/${SPACE}#key-ceremonies` },
            { key: 'add-administrator', label: 'Add an administrator', to: '/users' },
        ]);
        expect(spaceCeremonySettingsPath(SPACE)).toBe(`/spaces/${SPACE}#key-ceremonies`);
        expect(USERS_PATH).toBe('/users');
    });

    it('link a super to Settings for an instance ceremony', () => {
        const refusal = readCeremonyRefusal(refusalError({ requirementScope: 'instance', spaceId: null, spaceName: null }))!;
        expect(ceremonyRefusalLinks(refusal, SUPER)[0]).toEqual({
            key: 'instance-switch', label: 'Key ceremony settings for the instance', to: '/settings?tab=Security#key-ceremonies',
        });
        expect(INSTANCE_CEREMONY_SETTINGS_PATH).toBe('/settings?tab=Security#key-ceremonies');
    });

    it('offer the switch only to a caller the server says may turn it off', () => {
        const refusal = readCeremonyRefusal(refusalError({ canDisableRequirement: false }))!;
        expect(ceremonyRefusalLinks(refusal, SUPER).map((l) => l.key)).toEqual(['add-administrator']);
        // The server's word is not enough without the page being reachable.
        const allowed = readCeremonyRefusal(refusalError({}))!;
        expect(ceremonyRefusalLinks(allowed, { isSystemAdmin: false, canManageUsers: true }).map((l) => l.key)).toEqual(['add-administrator']);
    });

    it('offer nothing to a viewer who can do none of it, and say whom to ask', () => {
        const refusal = readCeremonyRefusal(refusalError({ canDisableRequirement: false }))!;
        const links = ceremonyRefusalLinks(refusal, OPERATOR);
        expect(links).toEqual([]);
        expect(ceremonyRefusalAdvice(refusal, links)).toBe(
            'Ask a system super-administrator to add another administrator, or to turn the key ceremony requirement off for space Acme.');
    });

    it('word the advice for what is offered', () => {
        const refusal = readCeremonyRefusal(refusalError({}))!;
        expect(ceremonyRefusalAdvice(refusal, ceremonyRefusalLinks(refusal, SUPER))).toBe(
            'Turn the key ceremony requirement off for space Acme, or add another administrator who can approve, then try again.');
        expect(ceremonyRefusalAdvice(refusal, ceremonyRefusalLinks(refusal, { isSystemAdmin: true, canManageUsers: false }))).toBe(
            'Turn the key ceremony requirement off for space Acme, then try again.');

        const tooFew = readCeremonyRefusal(refusalError({ code: CEREMONY_QUORUM_UNREACHABLE, requiredApprovals: 2, eligibleApprovers: 1, requirementScope: 'instance', spaceId: null }))!;
        expect(ceremonyRefusalAdvice(tooFew, ceremonyRefusalLinks(tooFew, SUPER))).toBe(
            'Turn the key ceremony requirement off or lower its approvals for the instance, or add another administrator who can approve, then try again.');

        // A policy change or a controlled-user change: no switch governs it.
        const ungoverned = readCeremonyRefusal(refusalError({ requirementScope: null, spaceId: null, canDisableRequirement: false }))!;
        expect(ceremonyRefusalAdvice(ungoverned, ceremonyRefusalLinks(ungoverned, { isSystemAdmin: true, canManageUsers: true }))).toBe(
            'Add another administrator who can approve, or ask a system super-administrator to make this change directly.');
        expect(ceremonyRefusalAdvice(ungoverned, [])).toBe(
            'Ask a system super-administrator to add another administrator, or to make this change directly.');
    });
});

describe('a pending ceremony nobody else can approve', () => {
    it('says so when no one can', () => {
        expect(stuckCeremonyNotice({ status: 'Pending', quorumReachable: false, approvalsStillNeeded: 1, eligibleApprovers: 0 }))
            .toBe('No one else can approve this ceremony, so it will stay pending until it expires.');
    });

    it('gives both numbers when some can but too few', () => {
        expect(stuckCeremonyNotice({ status: 'Pending', quorumReachable: false, approvalsStillNeeded: 2, eligibleApprovers: 1 }))
            .toBe('This ceremony still needs 2 approvals and only 1 other administrator can approve it, so it will stay pending until it expires.');
    });

    it('is silent when it can be approved, is not pending, or the server did not say', () => {
        expect(stuckCeremonyNotice({ status: 'Pending', quorumReachable: true, approvalsStillNeeded: 1, eligibleApprovers: 3 })).toBeNull();
        expect(stuckCeremonyNotice({ status: 'Cancelled', quorumReachable: false, eligibleApprovers: 0 })).toBeNull();
        expect(stuckCeremonyNotice({ status: 'Pending' })).toBeNull();
        expect(stuckCeremonyNotice({ status: 'Pending', quorumReachable: null })).toBeNull();
        expect(stuckCeremonyNotice(null)).toBeNull();
    });
});

describe('the warning before a requirement is saved', () => {
    const draft = { required: true, wasRequired: false, approvals: 1, eligibleApprovers: 0, scope: 'the instance' };

    it('warns before the requirement is turned on with nobody to approve', () => {
        expect(requirementWarning(draft)).toBe(
            'No other administrator can approve a key ceremony for the instance. If you turn this on, you will not be able to create, revoke or delete CAs of the instance until a second administrator exists.');
    });

    it('says the same of a requirement that is already on', () => {
        expect(requirementWarning({ ...draft, wasRequired: true, scope: 'this space' })).toBe(
            'Key ceremonies are on for this space, but no other administrator can approve one: you will not be able to create, revoke or delete CAs of this space until a second administrator exists.');
    });

    it('warns when the approvals asked for exceed the people who can give them', () => {
        expect(requirementWarning({ ...draft, approvals: 3, eligibleApprovers: 1 })).toBe(
            'A key ceremony for the instance would need 3 approvals and only 1 other administrator can approve. If you save this, you will not be able to create, revoke or delete CAs of the instance until more administrators can approve.');
    });

    it('is silent when off, when enough can approve, and when the count is unknown', () => {
        expect(requirementWarning({ ...draft, required: false })).toBeNull();
        expect(requirementWarning({ ...draft, eligibleApprovers: 1 })).toBeNull();
        expect(requirementWarning({ ...draft, approvals: 2, eligibleApprovers: 2 })).toBeNull();
        expect(requirementWarning({ ...draft, eligibleApprovers: null })).toBeNull();
    });
});
