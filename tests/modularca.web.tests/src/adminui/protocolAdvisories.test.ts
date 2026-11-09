import { describe, expect, it } from 'vitest';
import { advisoriesOf, protocolFindings } from '@adminui/pages/protocolAdvisories';

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

describe('the advisories of one configuration', () => {
    it('reads the array the server sent, and nothing else', () => {
        expect(advisoriesOf({ advisories: [scepOnEc] })).toEqual([scepOnEc]);
        expect(advisoriesOf({})).toEqual([]);
        expect(advisoriesOf(null)).toEqual([]);
    });
});
