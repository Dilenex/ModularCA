/** One reason a protocol configuration on a CA cannot work, as the API reports it. */
export interface ProtocolAdvisory {
    /** A stable code, e.g. `ScepRequiresRsaKey`. */
    reason: string;
    /** The sentence to show the operator. */
    message: string;
}

/** An enabled protocol configuration that cannot run on its CA. */
export interface ProtocolFinding {
    caId: string;
    caName: string;
    protocol: string;
    advisory: ProtocolAdvisory;
}

/** The notice for SCEP that accepts requests without a challenge password. */
export const SCEP_WITHOUT_CHALLENGE: ProtocolAdvisory = {
    reason: 'ScepWithoutChallenge',
    message: 'SCEP accepts requests without a challenge password: anyone who can reach this CA\'s SCEP endpoint '
        + 'can enroll. Turn on Require Challenge Password unless open enrollment is intended.',
};

/**
 * The notice for a protocol configuration that can run but is open by its own setting, unlike the
 * server's advisories, which say it cannot run: today SCEP with the challenge password off. Keyed
 * on the setting alone, so the protocol page can show it as the toggle changes; `requireEnabled`
 * leaves out a disabled row, for the CA page. A feed without the setting gives no notice.
 */
export function openEnrollmentNotice(config: any, requireEnabled = false): ProtocolAdvisory | null {
    if ((config?.protocol || '').toUpperCase() !== 'SCEP') return null;
    if (requireEnabled && !config?.enabled) return null;
    return config?.scepChallengeRequired === false ? SCEP_WITHOUT_CHALLENGE : null;
}

/** The advisories the server attached to one protocol configuration; empty when there are none. */
export function advisoriesOf(config: any): ProtocolAdvisory[] {
    return Array.isArray(config?.advisories) ? (config.advisories as ProtocolAdvisory[]) : [];
}

/**
 * Every enabled protocol configuration that cannot run on its CA, from the hierarchy feed,
 * children included, ordered by CA name and protocol. A disabled configuration is left out: it
 * refuses nothing, and enabling it again is refused where it is saved.
 */
export function protocolFindings(hierarchy: any[]): ProtocolFinding[] {
    const found: ProtocolFinding[] = [];
    const walk = (cas: any[]) => {
        for (const ca of cas || []) {
            for (const config of ca?.protocolConfigs || []) {
                if (!config?.enabled) continue;
                for (const advisory of advisoriesOf(config)) {
                    found.push({ caId: ca.id, caName: ca.name || ca.label || ca.id, protocol: config.protocol, advisory });
                }
            }
            walk(ca?.children);
        }
    };
    walk(hierarchy);
    return found.sort((a, b) => a.caName.localeCompare(b.caName) || a.protocol.localeCompare(b.protocol));
}
