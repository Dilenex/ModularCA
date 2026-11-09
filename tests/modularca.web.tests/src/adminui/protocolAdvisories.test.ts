import { describe, expect, it } from 'vitest';
import { advisoriesOf, openEnrollmentNotice, protocolFindings, SCEP_WITHOUT_CHALLENGE } from '@adminui/pages/protocolAdvisories';

const scepOnEc = { reason: 'ScepRequiresRsaKey', message: 'SCEP cannot run on this CA: its key is ECDSA.' };

describe('which protocol configurations System Health lists', () => {
    const hierarchy = [
        {
            id: 'root', name: 'Root', protocolConfigs: [{ protocol: 'EST', enabled: true, advisories: [] }],
            children: [
                { id: 'ec', name: 'EC Issuing', protocolConfigs: [
                    { protocol: 'SCEP', enabled: true, advisories: [scepOnEc] },
                    { protocol: 'EST', enabled: true, advisories: [] },
                ], children: [] },
                { id: 'ec-off', name: 'EC Off', protocolConfigs: [{ protocol: 'SCEP', enabled: false, advisories: [scepOnEc] }] },
            ],
        },
        { id: 'old', name: 'Old', protocolConfigs: [{ protocol: 'SCEP', enabled: true }] },
    ];

    it('lists an enabled configuration that carries an advisory, children included', () => {
        expect(protocolFindings(hierarchy)).toEqual([
            { caId: 'ec', caName: 'EC Issuing', protocol: 'SCEP', advisory: scepOnEc },
        ]);
    });

    it('leaves out a disabled one, one with nothing wrong, and one from a feed without advisories', () => {
        const ids = protocolFindings(hierarchy).map((f) => f.caId);
        expect(ids).not.toContain('ec-off');
        expect(ids).not.toContain('root');
        expect(ids).not.toContain('old');
    });

    it('is empty for an empty or missing feed', () => {
        expect(protocolFindings([])).toEqual([]);
        expect(protocolFindings(undefined as any)).toEqual([]);
    });
});

describe('the notice for SCEP open to requests without a challenge password', () => {
    it('is shown when the challenge password is off', () => {
        expect(openEnrollmentNotice({ protocol: 'SCEP', enabled: true, scepChallengeRequired: false })).toBe(SCEP_WITHOUT_CHALLENGE);
        expect(openEnrollmentNotice({ protocol: 'scep', enabled: false, scepChallengeRequired: false })).toBe(SCEP_WITHOUT_CHALLENGE);
        expect(SCEP_WITHOUT_CHALLENGE.message).toContain('without a challenge password');
    });

    it('is not shown when it is on, unknown, or for another protocol', () => {
        expect(openEnrollmentNotice({ protocol: 'SCEP', enabled: true, scepChallengeRequired: true })).toBeNull();
        expect(openEnrollmentNotice({ protocol: 'SCEP', enabled: true })).toBeNull();
        expect(openEnrollmentNotice({ protocol: 'EST', enabled: true, scepChallengeRequired: false })).toBeNull();
        expect(openEnrollmentNotice(null)).toBeNull();
    });

    it('leaves out a disabled configuration where asked to', () => {
        expect(openEnrollmentNotice({ protocol: 'SCEP', enabled: false, scepChallengeRequired: false }, true)).toBeNull();
        expect(openEnrollmentNotice({ protocol: 'SCEP', enabled: true, scepChallengeRequired: false }, true)).toBe(SCEP_WITHOUT_CHALLENGE);
    });
});

describe('the advisories of one configuration', () => {
    it('reads the array the server sent, and nothing else', () => {
        expect(advisoriesOf({ advisories: [scepOnEc] })).toEqual([scepOnEc]);
        expect(advisoriesOf({})).toEqual([]);
        expect(advisoriesOf(null)).toEqual([]);
    });
});
