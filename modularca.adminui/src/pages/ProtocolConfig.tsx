import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Link } from 'react-router-dom';
import { Chevron } from '@shared/components/Chevron';
import { apiGet, apiPut, apiPutWithMfa } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { StepUpOps } from '@shared/generated';
import { ToggleField, labelClass } from '@shared/components/forms';

// MSAE is Windows autoenrollment (MS-WSTEP over HTTPS). Its own fields are the two authentication
// modes: username (WS-Security UsernameToken / HTTP Basic) and Kerberos, which needs a realm bound
// on the tenant page.
const PROTOCOLS = ['EST', 'SCEP', 'CMP', 'ACME', 'OCSP', 'MSAE'];
const ACME_CHALLENGE_OPTIONS = ['http-01', 'dns-01', 'tls-alpn-01'];

/** One reason a protocol configuration on this CA cannot work, as the API reports it. */
interface ProtocolAdvisory {
    /** A stable code, e.g. `ScepRequiresRsaKey`. */
    reason: string;
    /** The sentence to show the operator. */
    message: string;
}

/**
 * The advisory for SCEP on an authority whose key is not RSA, written here for the card of a
 * protocol that has no configuration row yet; a row that exists carries the sentence the server
 * sent instead. Proven live: the client encrypts its request to the CA certificate with RSA key
 * transport, the only recipient type SCEP defines, so an ECDSA authority cannot serve it.
 */
const scepKeyAdvisory = (keyAlgorithm: string): ProtocolAdvisory => ({
    reason: 'ScepRequiresRsaKey',
    message: `SCEP cannot run on this CA: its key is ${keyAlgorithm}, and a SCEP client encrypts its `
        + 'certification request to the CA certificate using RSA key transport, the only recipient type '
        + 'SCEP defines. Serve SCEP from an RSA authority instead.',
});

const ProtocolConfig: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const { caId: scopeCaId } = useScope();
    const [selectedCaId, setSelectedCaId] = useState(scopeCaId ?? '');
    // Follow the sidebar scope: picking a CA there selects it here too.
    useEffect(() => {
        if (scopeCaId) { setSelectedCaId(scopeCaId); setExpandedProtocol(null); }
    }, [scopeCaId]);
    const [expandedProtocol, setExpandedProtocol] = useState<string | null>(null);
    const [protocolConfigs, setProtocolConfigs] = useState<any[]>([]);
    const [configLoading, setConfigLoading] = useState(false);
    // Protocols this deployment serves at all. Null until the system says so, and it stays null
    // when the lookup fails, which shows every protocol: a page that hid protocols because one
    // unrelated request failed would read as a system that no longer has them.
    const [systemProtocols, setSystemProtocols] = useState<string[] | null>(null);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [saving, setSaving] = useState<string | null>(null);

    const flattenCas = (cas: any[]): any[] => {
        const result: any[] = [];
        for (const ca of cas) {
            // Hide the System Signing CA — it never serves enrollment protocols.
            if ((ca.label || '').toLowerCase() === 'system-signing-ca') {
                if (ca.children && ca.children.length > 0) result.push(...flattenCas(ca.children));
                continue;
            }
            result.push(ca);
            if (ca.children && ca.children.length > 0) {
                result.push(...flattenCas(ca.children));
            }
        }
        return result;
    };

    // Which protocols the system feature flags leave switched on: the same list the public portal
    // advertises, so a protocol disabled system-wide is not offered for configuration here.
    useEffect(() => {
        apiGet<any>('/api/v1/public/info')
            .then((info) => {
                const enabled = info?.enabledProtocols;
                if (Array.isArray(enabled)) setSystemProtocols(enabled.map((p: string) => String(p).toUpperCase()));
            })
            .catch(() => setSystemProtocols(null));
    }, []);

    useEffect(() => {
        setLoading(true);
        Promise.all([
            apiGet<any>('/api/v1/admin/authorities/hierarchy'),
            apiGet<any>('/api/v1/admin/signing-profiles'),
            apiGet<any>('/api/v1/admin/cert-profiles'),
        ])
            .then(([caData, spData, cpData]) => {
                const items = Array.isArray(caData) ? caData : (caData.items || caData.authorities || []);
                setAuthorities(items);
                setSigningProfiles(Array.isArray(spData) ? spData : (spData.items || spData.profiles || []));
                setCertProfiles(Array.isArray(cpData) ? cpData : (cpData.items || cpData.profiles || []));
                const flat = flattenCas(items);
                if (flat.length > 0) {
                    const firstId = flat[0].id || flat[0].certificateId || flat[0].name || '';
                    // Keep a scoped CA; otherwise start on the first one.
                    setSelectedCaId((current) => current || firstId);
                }
                setLoading(false);
            })
            .catch((err) => {
                setError(errorNotice(err, 'Failed to load data'));
                setLoading(false);
            });
    }, []);

    useEffect(() => {
        if (!selectedCaId) return;
        setConfigLoading(true);
        apiGet<any>(`/api/v1/admin/protocol-configs/${selectedCaId}`)
            .then((data) => { setProtocolConfigs(Array.isArray(data) ? data : []); setError(null); })
            // A failed load must not paint every protocol "Not Configured": that reads as a true
            // state and sends the operator to re-enable things that are fine.
            .catch((err) => { setProtocolConfigs([]); setError(errorNotice(err, 'Could not load the protocol configuration for this CA.')); })
            .finally(() => setConfigLoading(false));
    }, [selectedCaId]);

    const allCasFlat = flattenCas(authorities);
    const selectedCa = allCasFlat.find((ca) => (ca.id || ca.certificateId || ca.name) === selectedCaId) || null;
    const caKeyAlgorithm: string = selectedCa?.keyAlgorithm || '';

    // A protocol disabled system-wide is refused at the edge, so it is not listed here either.
    const visibleProtocols = systemProtocols
        ? PROTOCOLS.filter((p) => systemProtocols.includes(p))
        : PROTOCOLS;
    const hiddenProtocols = PROTOCOLS.filter((p) => !visibleProtocols.includes(p));

    /**
     * What is wrong with this protocol on this CA: the advisories the server attached to a
     * configured row, or the one we can tell without a row, SCEP on a non-RSA authority.
     */
    const advisoriesFor = (protocol: string, config: any): ProtocolAdvisory[] => {
        if (config) return (config.advisories as ProtocolAdvisory[]) || [];
        if (protocol === 'SCEP' && caKeyAlgorithm && caKeyAlgorithm.toUpperCase() !== 'RSA')
            return [scepKeyAdvisory(caKeyAlgorithm)];
        return [];
    };

    const getProtocolConfig = (protocol: string): any | null => {
        return protocolConfigs.find(
            (pc: any) => (pc.protocol || '').toUpperCase() === protocol.toUpperCase()
        ) || null;
    };

    const handleSave = async (protocol: string, updates: any) => {
        setSaving(protocol);
        try {
            await apiPutWithMfa(`/api/v1/admin/protocol-configs/${selectedCaId}/${protocol}`, updates, requireStepUp, StepUpOps.UpdateProtocolConfig, selectedCaId);
            const data = await apiGet<any>(`/api/v1/admin/protocol-configs/${selectedCaId}`);
            setProtocolConfigs(Array.isArray(data) ? data : []);
        } catch (err: any) {
            showToast('error', err.message || `Failed to update ${protocol} config`);
        } finally {
            setSaving(null);
        }
    };

    const selectClass = 'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500';

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Protocol Configuration</h1>

            {/* CA Selector */}
            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Select Certificate Authority</h3>
                </div>
                <div className="p-4">
                    {loading && <p className="text-sm text-gray-600 dark:text-gray-400">Loading authorities...</p>}
                    {error && <InlineNotice notice={error} variant="line" />}
                    {!loading && !error && (
                        <select
                            value={selectedCaId}
                            onChange={(e) => {
                                setSelectedCaId(e.target.value);
                                setExpandedProtocol(null);
                            }}
                            className="w-full max-w-md px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                        >
                            {allCasFlat.length === 0 && <option value="">No CAs available</option>}
                            {allCasFlat.map((ca) => {
                                const id = ca.id || ca.certificateId || ca.name;
                                return (
                                    <option key={id} value={id}>
                                        {ca.name || ca.subjectDN}
                                    </option>
                                );
                            })}
                        </select>
                    )}
                </div>
            </div>

            {configLoading && <div className="p-4 text-sm text-gray-600 dark:text-gray-400">Loading protocol configs...</div>}

            {/* Protocol Cards */}
            {selectedCaId && !configLoading && visibleProtocols.length === 0 && (
                <InlineNotice
                    severity="info"
                    notice={{
                        title: 'No enrollment protocols are enabled on this system',
                        detail: `${PROTOCOLS.join(', ')} are all switched off by their system feature flags, so there is nothing to configure here.`,
                        remediation: 'Turn a protocol on under Settings \u2192 Features; the configuration it had is still there.',
                    }}
                />
            )}
            {selectedCaId && !configLoading && hiddenProtocols.length > 0 && visibleProtocols.length > 0 && (
                <p className="text-xs text-gray-600 dark:text-gray-400">
                    Not listed: {hiddenProtocols.join(', ')} &mdash; disabled system-wide under{' '}
                    <Link to="/settings" className="text-blue-600 dark:text-blue-400 hover:underline">Settings &rarr; Features</Link>.
                    Their configuration is kept and returns when the flag does.
                </p>
            )}
            {selectedCaId && !configLoading && visibleProtocols.map((protocol) => {
                const config = getProtocolConfig(protocol);
                const expanded = expandedProtocol === protocol;

                return (
                    <ProtocolCard
                        caId={selectedCaId}
                        key={protocol}
                        protocol={protocol}
                        config={config}
                        expanded={expanded}
                        onToggleExpand={() => setExpandedProtocol(expanded ? null : protocol)}
                        onSave={(updates) => handleSave(protocol, updates)}
                        saving={saving === protocol}
                        advisories={advisoriesFor(protocol, config)}
                        signingProfiles={signingProfiles}
                        certProfiles={certProfiles}
                        labelClass={labelClass}
                        selectClass={selectClass}
                    />
                );
            })}

            {!selectedCaId && !loading && !error && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-6 text-center">
                    <p className="text-sm text-gray-600">Select a Certificate Authority above to view protocol configurations.</p>
                </div>
            )}
        </div>
    );
};

interface ProtocolCardProps {
    /** The CA whose card this is; the Windows readiness page is keyed by it. */
    caId: string;
    protocol: string;
    config: any;
    expanded: boolean;
    onToggleExpand: () => void;
    onSave: (updates: any) => void;
    saving: boolean;
    /** Reasons this protocol cannot work on this CA, if any; shown before anything is saved. */
    advisories: ProtocolAdvisory[];
    signingProfiles: any[];
    certProfiles: any[];
    labelClass: string;
    selectClass: string;
}

const ProtocolCard: React.FC<ProtocolCardProps> = ({
    caId,
    protocol, config, expanded, onToggleExpand, onSave, saving, advisories,
    signingProfiles, certProfiles, labelClass, selectClass,
}) => {
    const [form, setForm] = useState<Record<string, any>>({
        enabled: false,
        signingProfileId: '',
        certProfileId: '',
        isPublicVisible: true,
        // EST
        estRequireClientCert: false,
        estHttpAuthEnabled: false,
        // SCEP
        scepChallengeRequired: true,
        // CMP
        cmpRequireSignature: false,
        cmpSignerConfigured: true,
        // ACME
        acmeRequireEab: false,
        acmeAllowedChallengeTypes: '',
        acmeAllowPrivateAddressValidation: false,
        // OCSP
        ocspSignResponses: true,
        // MSAE
        msaeAllowUsernameToken: true,
        msaeAllowKerberos: false,
    });

    useEffect(() => {
        if (config) {
            setForm({
                enabled: config.enabled ?? false,
                signingProfileId: config.signingProfileId || '',
                certProfileId: config.certProfileId || '',
                isPublicVisible: config.isPublicVisible ?? true,
                estRequireClientCert: config.estRequireClientCert ?? false,
                estHttpAuthEnabled: config.estHttpAuthEnabled ?? false,
                scepChallengeRequired: config.scepChallengeRequired ?? true,
                cmpRequireSignature: config.cmpRequireSignature ?? false,
                cmpSignerConfigured: config.cmpSignerConfigured ?? true,
                acmeRequireEab: config.acmeRequireEab ?? false,
                acmeAllowedChallengeTypes: config.acmeAllowedChallengeTypes || '',
                acmeAllowPrivateAddressValidation: config.acmeAllowPrivateAddressValidation ?? false,
                ocspSignResponses: config.ocspSignResponses ?? true,
                msaeAllowUsernameToken: config.msaeAllowUsernameToken ?? true,
                msaeAllowKerberos: config.msaeAllowKerberos ?? false,
            });
        } else {
            setForm({
                enabled: false, signingProfileId: '', certProfileId: '',
                isPublicVisible: true,
                estRequireClientCert: false, estHttpAuthEnabled: false,
                scepChallengeRequired: true,
                cmpRequireSignature: false, cmpSignerConfigured: true,
                acmeRequireEab: false, acmeAllowedChallengeTypes: '',
                acmeAllowPrivateAddressValidation: false,
                ocspSignResponses: true,
                msaeAllowUsernameToken: true, msaeAllowKerberos: false,
            });
        }
    }, [config]);

    const handleSubmit = () => {
        const base: Record<string, any> = {
            enabled: form.enabled,
            signingProfileId: form.signingProfileId || null,
            certProfileId: form.certProfileId || null,
            isPublicVisible: form.isPublicVisible,
        };
        if (protocol === 'EST') {
            base.estRequireClientCert = form.estRequireClientCert;
            base.estHttpAuthEnabled = form.estHttpAuthEnabled;
        } else if (protocol === 'SCEP') {
            base.scepChallengeRequired = form.scepChallengeRequired;
        } else if (protocol === 'CMP') {
            base.cmpRequireSignature = form.cmpRequireSignature;
        } else if (protocol === 'ACME') {
            base.acmeRequireEab = form.acmeRequireEab;
            base.acmeAllowedChallengeTypes = form.acmeAllowedChallengeTypes || null;
            base.acmeAllowPrivateAddressValidation = form.acmeAllowPrivateAddressValidation;
        } else if (protocol === 'OCSP') {
            base.ocspSignResponses = form.ocspSignResponses;
        } else if (protocol === 'MSAE') {
            base.msaeAllowUsernameToken = form.msaeAllowUsernameToken;
            base.msaeAllowKerberos = form.msaeAllowKerberos;
        }
        onSave(base);
    };

    const needsProfiles = protocol !== 'OCSP';

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
            <button
                onClick={onToggleExpand}
                className="w-full px-4 py-3 flex items-center gap-3 text-left hover:bg-gray-200/50 dark:bg-gray-700/50 transition-colors"
            >
                <span className="text-gray-600 text-xs"><Chevron open={expanded} className="w-3 h-3" /></span>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">{protocol}</span>
                {config ? (
                    <StatusBadge
                        status={config.enabled ? 'enabled' : 'disabled'}
                        label={config.enabled ? 'Enabled' : 'Disabled'}
                    />
                ) : (
                    <StatusBadge status="disabled" label="Not Configured" />
                )}
                {advisories.length > 0 && (
                    <span className="text-xs font-medium text-amber-700 dark:text-amber-400">Cannot run on this CA</span>
                )}
                {config?.signingProfileName && (
                    <span className="text-xs text-gray-600 ml-auto">Signing: {config.signingProfileName}</span>
                )}
            </button>
            {expanded && (
                <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                    {advisories.map((a) => (
                        <InlineNotice
                            key={a.reason}
                            severity="warning"
                            notice={{ title: `${protocol} cannot run on this CA`, detail: a.message, code: a.reason }}
                        />
                    ))}
                    {/* Common fields */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label className={labelClass}>Enabled</label>
                            <select
                                value={form.enabled ? 'true' : 'false'}
                                onChange={(e) => setForm({ ...form, enabled: e.target.value === 'true' })}
                                className={selectClass}
                            >
                                <option value="true">Yes</option>
                                <option value="false">No</option>
                            </select>
                        </div>
                        {needsProfiles && (
                            <>
                                <div>
                                    <label className={labelClass}>Signing Profile</label>
                                    <select value={form.signingProfileId} onChange={(e) => setForm({ ...form, signingProfileId: e.target.value })} className={selectClass}>
                                        <option value="">Not assigned</option>
                                        {signingProfiles.map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}
                                    </select>
                                </div>
                                <div>
                                    <label className={labelClass}>Certificate Profile</label>
                                    <select value={form.certProfileId} onChange={(e) => setForm({ ...form, certProfileId: e.target.value })} className={selectClass}>
                                        <option value="">Not assigned</option>
                                        {certProfiles.map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}
                                    </select>
                                </div>
                            </>
                        )}
                    </div>

                    {/* Visibility & Access Control */}
                    <div className="border-t border-gray-300 dark:border-gray-700 pt-3">
                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-2">Visibility &amp; Access</h4>
                        <div className="space-y-3">
                            <ToggleField size="md" labelSide="left"
                                label="Show on Public Portal"
                                description="When unchecked, this protocol endpoint won't appear on the public portal for this CA"
                                checked={form.isPublicVisible}
                                onChange={(v) => setForm({ ...form, isPublicVisible: v })}
                            />
                        </div>
                    </div>

                    {/* Protocol-specific fields */}
                    <div className="border-t border-gray-300 dark:border-gray-700 pt-3">
                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-2">{protocol} Settings</h4>

                        {protocol === 'EST' && (
                            <div className="space-y-2">
                                <ToggleField size="md" labelSide="left" label="Require Client Certificate" description="Clients must present a valid certificate for enrollment" checked={form.estRequireClientCert} onChange={(v) => setForm({ ...form, estRequireClientCert: v })} />
                                <ToggleField size="md" labelSide="left" label="HTTP Authentication" description="Accept HTTP Basic/Digest authentication for enrollment" checked={form.estHttpAuthEnabled} onChange={(v) => setForm({ ...form, estHttpAuthEnabled: v })} />
                            </div>
                        )}

                        {protocol === 'SCEP' && (
                            <div className="space-y-2">
                                <ToggleField size="md" labelSide="left" label="Require Challenge Password" description="CSR must include a challenge password for enrollment" checked={form.scepChallengeRequired} onChange={(v) => setForm({ ...form, scepChallengeRequired: v })} />
                            </div>
                        )}

                        {protocol === 'CMP' && (
                            <div className="space-y-3">
                                {form.enabled && !form.cmpSignerConfigured && (
                                    <div className="rounded border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/30 p-3">
                                        <p className="text-xs text-amber-900 dark:text-amber-300">
                                            <strong>This CA has no CMP signing certificate.</strong> Signature-protected
                                            responses are signed with the CA certificate, which OpenSSL-based clients reject.
                                            Shared-secret (PBMAC) clients work without it. Issue one from the CA's detail page
                                            under Infrastructure Certificates.
                                        </p>
                                    </div>
                                )}
                                <ToggleField size="md" labelSide="left" label="Require Signature Protection" description="When enabled, only signature-based protection is accepted (client cert required). When disabled, PBMAC (shared secret) is also accepted." checked={form.cmpRequireSignature} onChange={(v) => setForm({ ...form, cmpRequireSignature: v })} />
                                <p className="text-[10px] text-gray-600 mt-1">
                                    PBMAC shared secrets are issued per client from{' '}
                                    <Link to="/enrollment" className="text-blue-600 dark:text-blue-400 hover:underline">Enrollment Management</Link>,
                                    which replaced the old single per-CA secret. Generate one there rather than sharing a CA-wide password.
                                </p>
                            </div>
                        )}

                        {protocol === 'ACME' && (
                            <div className="space-y-3">
                                <ToggleField size="md" labelSide="left" label="Require External Account Binding" description="Accounts must provide an EAB key during registration (RFC 8555 \u00A77.3.4)" checked={form.acmeRequireEab} onChange={(v) => setForm({ ...form, acmeRequireEab: v })} />
                                <ToggleField size="md" labelSide="left" label="Allow Private Address Validation (HTTP-01)" description="Permit the http-01 validator to fetch challenges from RFC 1918 / loopback / link-local addresses, and to resolve identifiers via the server's OS hosts file (/etc/hosts or the Windows hosts file) in addition to DNS. Required for internal-only PKI; leave off for public deployments to prevent SSRF." checked={form.acmeAllowPrivateAddressValidation} onChange={(v) => setForm({ ...form, acmeAllowPrivateAddressValidation: v })} />
                                <div>
                                    <label className={labelClass}>Allowed Challenge Types</label>
                                    <div className="flex gap-3 mt-1">
                                        {ACME_CHALLENGE_OPTIONS.map((ct) => {
                                            const types = (form.acmeAllowedChallengeTypes || '').split(',').filter(Boolean);
                                            const checked = types.includes(ct);
                                            return (
                                                <label key={ct} className="flex items-center gap-1.5 text-xs text-gray-700 dark:text-gray-300 cursor-pointer">
                                                    <input type="checkbox" checked={checked} onChange={(e) => {
                                                        const next = e.target.checked ? [...types, ct] : types.filter((t: string) => t !== ct);
                                                        setForm({ ...form, acmeAllowedChallengeTypes: next.join(',') });
                                                    }} className="w-3.5 h-3.5 accent-blue-500" />
                                                    {ct}
                                                </label>
                                            );
                                        })}
                                    </div>
                                    <p className="text-[10px] text-gray-600 mt-1">Leave all unchecked to allow all challenge types.</p>
                                </div>
                            </div>
                        )}

                        {protocol === 'OCSP' && (
                            <div className="space-y-2">
                                <ToggleField size="md" labelSide="left" label="Sign Responses" description="Sign OCSP responses with the CA's OCSP responder key" checked={form.ocspSignResponses} onChange={(v) => setForm({ ...form, ocspSignResponses: v })} />
                            </div>
                        )}

                        {protocol === 'MSAE' && caId && (
                            <p className="text-xs text-gray-600 dark:text-gray-400">
                                Authentication is only one prerequisite. <Link to={`/authorities/windows/${caId}`} className="text-blue-600 dark:text-blue-400 hover:underline">Windows Autoenrollment</Link> checks all of them for this CA.
                            </p>
                        )}
                        {protocol === 'MSAE' && (
                            <div className="space-y-2">
                                <ToggleField size="md" labelSide="left" label="Username authentication" description="Accept the WS-Security UsernameToken (and HTTP Basic) a client configured for username authentication sends" checked={form.msaeAllowUsernameToken} onChange={(v) => setForm({ ...form, msaeAllowUsernameToken: v })} />
                                <ToggleField size="md" labelSide="left" label="Windows integrated authentication (Kerberos)" description="Accept tickets from the Active Directory forests bound to this CA's tenant, and challenge credential-less clients with 401. Needs a realm bound on the tenant page." checked={form.msaeAllowKerberos} onChange={(v) => setForm({ ...form, msaeAllowKerberos: v })} />
                                {!form.msaeAllowUsernameToken && !form.msaeAllowKerberos && (
                                    <p className="text-xs text-amber-700 dark:text-amber-400">At least one authentication method must stay enabled.</p>
                                )}
                            </div>
                        )}
                    </div>

                    <div className="flex justify-end">
                        <button
                            onClick={handleSubmit}
                            disabled={saving}
                            className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                        >
                            {saving ? 'Saving...' : (config ? 'Update' : 'Create Configuration')}
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ProtocolConfig;
