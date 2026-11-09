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
