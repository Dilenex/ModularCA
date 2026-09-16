import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPost, apiPostWithMfa, apiDeleteWithMfa, apiBlob } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { StepUpOps } from '@shared/generated';
import { FieldHint } from '@shared/components/forms';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function downloadText(content: string, filename: string) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

/* ─── SSH CA Keys Section ─── */
const SshCaKeys: React.FC<{ refreshTrigger: number; onRefresh: () => void }> = ({ refreshTrigger, onRefresh }) => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [keys, setKeys] = useState<any[]>([]);
    const [tenants, setTenants] = useState<any[]>([]);
    const [pendingCeremonies, setPendingCeremonies] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [generating, setGenerating] = useState(false);
    const [genForm, setGenForm] = useState({ name: '', keyType: 'ed25519', keySize: '', isUserCa: true, isHostCa: false, maxValidityHours: '720', tenantId: '' });
    const [showGenForm, setShowGenForm] = useState(false);
    const [confirmAction, setConfirmAction] = useState<{ action: () => Promise<void>; title: string; message: string; confirmLabel: string } | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);

        Promise.all([
            apiGet<any>('/api/v1/admin/ssh/ca-keys'),
            apiGet<any>('/api/v1/admin/tenants'),
            apiGet<any>('/api/v1/admin/ceremonies?status=Pending').catch(() => []),
        ]).then(([keyData, tenantData, ceremonyData]) => {
                if (cancelled) return;
                setKeys(Array.isArray(keyData) ? keyData : (keyData.items || keyData.keys || []));
                setTenants(Array.isArray(tenantData) ? tenantData : (tenantData.items || tenantData.tenants || []));
                const allCeremonies = Array.isArray(ceremonyData) ? ceremonyData : (ceremonyData.items || []);
                setPendingCeremonies(allCeremonies.filter((c: any) =>
                    c.operationType === 'CreateSshCa' || c.operationType === 'DeleteSshCa'));
                setLoading(false);
            })
            .catch((err) => {
                if (!cancelled) {
                    setError(errorNotice(err, 'Failed to load SSH CA keys'));
                    setLoading(false);
                }
            });

        return () => { cancelled = true; };
    }, [refreshTrigger]);

    // A key that is neither a user nor a host CA is useless and the server would accept it anyway.
    const caRoleMissing = !genForm.isUserCa && !genForm.isHostCa;

    const handleGenerate = async (e: React.FormEvent) => {
        e.preventDefault();
        if (caRoleMissing) return;
        setGenerating(true);
        try {
            const result: any = await apiPostWithMfa('/api/v1/admin/ssh/ca-keys', {
                name: genForm.name || 'SSH CA Key',
                keyType: genForm.keyType,
                keySize: genForm.keySize ? parseInt(genForm.keySize) : undefined,
                isUserCa: genForm.isUserCa,
                isHostCa: genForm.isHostCa,
                maxValidityHours: parseInt(genForm.maxValidityHours) || 720,
                tenantId: genForm.tenantId || undefined,
            }, requireStepUp, StepUpOps.CreateSshCa);
            if (result?.requiresCeremony) {
                showToast('info', result.message || 'Key ceremony created for approval.');
                setShowGenForm(false);
                setGenForm({ name: '', keyType: 'ed25519', keySize: '', isUserCa: true, isHostCa: false, maxValidityHours: '720', tenantId: '' });
                return;
            }
            setShowGenForm(false);
            setGenForm({ name: '', keyType: 'ed25519', keySize: '', isUserCa: true, isHostCa: false, maxValidityHours: '720', tenantId: '' });
            onRefresh();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled')
                showToast('error', err.message || 'Failed to generate CA key');
        } finally {
            setGenerating(false);
        }
    };

    const handleDisableKey = (keyId: string, keyName: string) => {
        setConfirmAction({
            title: 'Disable SSH CA Key',
            message: `Are you sure you want to disable "${keyName}"? All active certificates will be revoked. This action cannot be undone.`,
            confirmLabel: 'Disable',
            action: async () => {
                const result: any = await apiDeleteWithMfa(
                    `/api/v1/admin/ssh/ca-keys/${keyId}`,
                    requireStepUp, StepUpOps.DisableSshCa, keyId);
                if (result?.requiresCeremony) {
                    showToast('info', result.message || 'Key ceremony created for approval.');
                } else {
                    showToast('success', 'CA key disabled successfully.');
                    onRefresh();
                }
            },
        });
    };

    // Build a combined list: real keys + pending ceremony placeholders
    const pendingCreateEntries = pendingCeremonies
        .filter((c: any) => c.operationType === 'CreateSshCa')
        .map((c: any) => ({
            id: `ceremony-${c.id}`,
            ceremonyId: c.id,
            name: c.description?.replace(/^Create SSH CA '/, '').replace(/'$/, '') || 'Pending SSH CA',
            keyType: '—',
            isUserCa: false,
            isHostCa: false,
            isEnabled: true,
            isPendingCeremony: true,
            ceremonyStatus: c.status,
            currentApprovals: c.currentApprovals,
            requiredApprovals: c.requiredApprovals,
        }));

    const keyStatusLabel = (key: any) => key.isEnabled === false
        ? 'Disabled'
        : (pendingCeremonies.some((c: any) => c.targetEntityId === key.id && c.operationType === 'DeleteSshCa') ? 'Disable Pending' : 'CA Key');
    const keyStatusBadge = (key: any) => {
        if (key.isEnabled === false) return <StatusBadge status="revoked" label="Disabled" />;
        if (pendingCeremonies.some((c: any) => c.targetEntityId === key.id && c.operationType === 'DeleteSshCa')) return <StatusBadge status="pending" label="Disable Pending" />;
        return <StatusBadge status="active" label="CA Key" />;
    };

    const columns: DataTableColumn<any>[] = [
        { key: 'name', header: 'Name', defaultWidth: 200, minWidth: 140, truncate: false, exportValue: (k) => k.name || 'Unnamed', render: (k) => <span className="text-gray-900 dark:text-white font-medium truncate">{k.name || 'Unnamed'}</span> },
        { key: 'status', header: 'Status', defaultWidth: 130, truncate: false, exportValue: keyStatusLabel, render: keyStatusBadge },
        { key: 'algorithm', header: 'Algorithm', defaultWidth: 150, exportValue: (k) => `${k.keyType || k.algorithm}${k.keySize ? ` (${k.keySize})` : ''}`, render: (k) => <span className="text-xs text-gray-700 dark:text-gray-300">{k.keyType || k.algorithm}{k.keySize ? ` (${k.keySize})` : ''}</span> },
        {
            key: 'role', header: 'Role', defaultWidth: 120, truncate: false,
            exportValue: (k) => [k.isUserCa ? 'User' : null, k.isHostCa ? 'Host' : null].filter(Boolean).join(', '),
            render: (k) => (
                <span className="flex gap-1">
                    {k.isUserCa && <span className="px-1.5 py-0.5 text-xs bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-400 rounded">User</span>}
                    {k.isHostCa && <span className="px-1.5 py-0.5 text-xs bg-purple-100 dark:bg-purple-900/50 text-purple-700 dark:text-purple-400 rounded">Host</span>}
                    {!k.isUserCa && !k.isHostCa && <span className="text-xs text-gray-500">-</span>}
                </span>
            ),
        },
        { key: 'created', header: 'Created', defaultWidth: 160, exportValue: (k) => formatDate(k.createdAt), render: (k) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(k.createdAt)}</span> },
    ];

    // Disable is step-up MFA gated with no bulk endpoint, so it's single-select.
    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Disable', single: true, variant: 'danger', enabledFor: (k) => k.isEnabled !== false, onClick: (rows) => handleDisableKey(rows[0].id, rows[0].name) },
    ];

    const caKeyDrawer = (k: any) => (
        <div className="text-sm">
            <DetailField label="ID" value={k.id} mono />
            <DetailField label="Status" value={keyStatusLabel(k)} />
            <DetailField label="Algorithm" value={`${k.keyType || k.algorithm}${k.keySize ? ` (${k.keySize} bits)` : ''}`} />
            <DetailField label="Max Validity" value={`${k.maxValidityHours}h`} />
            <DetailField label="Created" value={formatDate(k.createdAt)} />
            <DetailField label="User CA" value={k.isUserCa ? 'Yes' : 'No'} />
            <DetailField label="Host CA" value={k.isHostCa ? 'Yes' : 'No'} />
            <DetailField label="Public Key" value={k.publicKey} mono />
        </div>
    );

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">SSH CA Keys</h2>
                <button
                    onClick={() => setShowGenForm(!showGenForm)}
                    className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 transition-colors"
                >
                    {showGenForm ? 'Cancel' : 'Generate CA Key'}
                </button>
            </div>

            {showGenForm && (
                <form onSubmit={handleGenerate} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Generate New SSH CA Key</h3>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Name</label>
                            <input
                                type="text"
                                required
                                placeholder="My SSH CA"
                                value={genForm.name}
                                onChange={(e) => setGenForm({ ...genForm, name: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500"
                            />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Key Type</label>
                            <select
                                value={genForm.keyType}
                                onChange={(e) => setGenForm({ ...genForm, keyType: e.target.value, keySize: '' })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                            >
                                <option value="ed25519">ed25519</option>
                                <option value="ecdsa">ecdsa</option>
                                <option value="rsa">rsa</option>
                            </select>
                        </div>
                        {genForm.keyType !== 'ed25519' && (
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Key Size</label>
                            <select
                                value={genForm.keySize}
                                onChange={(e) => setGenForm({ ...genForm, keySize: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                            >
                                {genForm.keyType === 'rsa' ? (
                                    <>
                                        <option value="">Default (3072)</option>
                                        <option value="2048">2048 bits</option>
                                        <option value="3072">3072 bits</option>
                                        <option value="4096">4096 bits</option>
                                        <option value="7680">7680 bits (high compute)</option>
                                        <option value="8192">8192 bits (high compute)</option>
                                    </>
                                ) : (
                                    <>
                                        <option value="">Default (256)</option>
                                        <option value="256">P-256 (256 bits)</option>
                                        <option value="384">P-384 (384 bits)</option>
                                        <option value="521">P-521 (521 bits)</option>
                                    </>
                                )}
                            </select>
                            {genForm.keyType === 'rsa' && (genForm.keySize === '7680' || genForm.keySize === '8192') && (
                                <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                                    ⚠ High-compute RSA — key generation may take 30+ seconds.
                                </p>
                            )}
                        </div>
                        )}
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Max Validity (hours)</label>
                            <input
                                type="text"
                                inputMode="numeric"
                                value={genForm.maxValidityHours}
                                onChange={(e) => setGenForm({ ...genForm, maxValidityHours: e.target.value.replace(/\D/g, '') })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500"
                            />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Tenant</label>
                            <select
                                value={genForm.tenantId}
                                onChange={(e) => setGenForm({ ...genForm, tenantId: e.target.value })}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                            >
                                <option value="">Select tenant...</option>
                                {tenants.map((t: any) => (
                                    <option key={t.id} value={t.id}>{t.name || t.id}</option>
                                ))}
                            </select>
                        </div>
                    </div>
                    <div>
                        <div className="flex gap-4">
                            <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                                <input type="checkbox" checked={genForm.isUserCa} onChange={(e) => setGenForm({ ...genForm, isUserCa: e.target.checked })} className="rounded" />
                                User CA
                            </label>
                            <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                                <input type="checkbox" checked={genForm.isHostCa} onChange={(e) => setGenForm({ ...genForm, isHostCa: e.target.checked })} className="rounded" />
                                Host CA
                            </label>
                        </div>
                        {caRoleMissing ? (
                            <FieldHint tone="warn">Choose at least one role. A key that is neither a User CA nor a Host CA can be trusted by nothing and can sign nothing.</FieldHint>
                        ) : (
                            <FieldHint>A User CA signs certificates that people present to servers; a Host CA signs certificates that servers present to clients. One key may do both, but separate keys keep a host-key leak from minting user access.</FieldHint>
                        )}
                    </div>
                    <button
                        type="submit"
                        disabled={generating || caRoleMissing}
                        className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                    >
                        {generating ? 'Generating...' : 'Generate'}
                    </button>
                </form>
            )}

            {pendingCreateEntries.length > 0 && (
                <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-lg p-3 text-xs space-y-1">
                    <p className="font-semibold text-amber-800 dark:text-amber-300">Pending CA key ceremonies</p>
                    {pendingCreateEntries.map((c) => (
                        <div key={c.id} className="flex items-center gap-2">
                            <StatusBadge status="pending" label={`Ceremony (${c.currentApprovals}/${c.requiredApprovals})`} />
                            <span className="text-gray-700 dark:text-gray-300">{c.name}</span>
                        </div>
                    ))}
                </div>
            )}

            <DataTable<any>
                tableId="ssh-ca-keys"
                title="SSH CA Keys"
                rows={keys}
                rowKey={(k) => k.id || k.fingerprint}
                loading={loading}
                error={error}
                empty="No SSH CA keys configured"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="ssh-ca-keys"
                renderDrawer={caKeyDrawer}
                drawerTitle={(k) => k.name || 'Unnamed'}
                detailPath={(k) => `/ssh/ca-keys/${k.id}`}
            />

            <ConfirmModal
                isOpen={!!confirmAction}
                title={confirmAction?.title || ''}
                message={confirmAction?.message || ''}
                confirmLabel={confirmAction?.confirmLabel || 'Confirm'}
                confirmClass="bg-red-600 hover:bg-red-700"
                loading={confirmLoading}
                onConfirm={async () => {
                    if (!confirmAction) return;
                    setConfirmLoading(true);
                    try {
                        await confirmAction.action();
                    } catch (err: any) {
                        if (err.message !== 'Step-up MFA cancelled')
                            showToast('error', err.message || 'Action failed');
                    } finally {
                        setConfirmLoading(false);
                        setConfirmAction(null);
                    }
                }}
                onCancel={() => setConfirmAction(null)}
            />
        </div>
    );
};

/* ─── Helpers ─── */
function parseJsonArray(val: any): string[] {
    if (Array.isArray(val)) return val;
    if (typeof val === 'string') {
        try { const parsed = JSON.parse(val); if (Array.isArray(parsed)) return parsed; } catch { }
    }
    return [];
}

/* ─── SSH Certificates Section ─── */
const SshCerts: React.FC<{ refreshTrigger: number; onRefresh: () => void; caKeys: any[] }> = ({ refreshTrigger, onRefresh, caKeys }) => {
    const { showToast } = useToast();
    const [certs, setCerts] = useState<any[]>([]);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [requestProfiles, setRequestProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [showSignForm, setShowSignForm] = useState(false);
    const [confirmRevoke, setConfirmRevoke] = useState<any[] | null>(null);
    const [signForm, setSignForm] = useState({ certType: 'user' as 'user' | 'host', sshRequestProfileId: '', sshSigningProfileId: '', sshCertProfileId: '', publicKey: '', identity: '', principals: '', allowAnyPrincipal: false, validityHours: '' });
    const [validationErrors, setValidationErrors] = useState<string[]>([]);
    const [signing, setSigning] = useState(false);
    const [signResult, setSignResult] = useState<any>(null);
    const [revoking, setRevoking] = useState<string | null>(null);
    const [selectedCaKeyId, setSelectedCaKeyId] = useState<string>('');

    // Auto-select first CA key when available
    useEffect(() => {
        if (caKeys.length > 0 && !selectedCaKeyId) {
            setSelectedCaKeyId(caKeys[0].id);
        }
    }, [caKeys]);

    useEffect(() => {
        if (!selectedCaKeyId) return;
        let cancelled = false;
        setLoading(true);
        setError(null);

        Promise.all([
            apiGet<any>(`/api/v1/admin/ssh/ca-keys/${selectedCaKeyId}/certificates`),
            apiGet<any>('/api/v1/admin/ssh/profiles/signing'),
            apiGet<any>('/api/v1/admin/ssh/profiles/cert'),
            apiGet<any>('/api/v1/admin/ssh/profiles/request'),
        ]).then(([certData, signingData, certProfData, reqProfData]) => {
                if (cancelled) return;
                setCerts(Array.isArray(certData) ? certData : (certData.items || certData.certificates || []));
                setSigningProfiles(Array.isArray(signingData) ? signingData : []);
                setCertProfiles(Array.isArray(certProfData) ? certProfData : []);
                setRequestProfiles(Array.isArray(reqProfData) ? reqProfData : []);
                setLoading(false);
            })
            .catch((err) => {
                if (!cancelled) {
                    setError(errorNotice(err, 'Failed to load SSH data'));
                    setLoading(false);
                }
            });

        return () => { cancelled = true; };
    }, [refreshTrigger, selectedCaKeyId]);

    // Derive allowed signing/cert profiles from the selected request profile
    const selectedRequestProfile = requestProfiles.find((p: any) => p.id === signForm.sshRequestProfileId);
    const allowedSigningIds = new Set(parseJsonArray(selectedRequestProfile?.allowedSshSigningProfileIds));
    const allowedCertIds = new Set(parseJsonArray(selectedRequestProfile?.allowedSshCertProfileIds));

    // Filter signing profiles by: matches selected CA key AND allowed in request profile AND matches cert type (user/host)
    const filteredSigningProfiles = signingProfiles.filter((p: any) => {
        if (p.sshCaKeyId !== selectedCaKeyId) return false;
        if (allowedSigningIds.size > 0 && !allowedSigningIds.has(p.id)) return false;
        if (signForm.certType === 'user' && !p.allowUserCerts) return false;
        if (signForm.certType === 'host' && !p.allowHostCerts) return false;
        return true;
    });
    const filteredCertProfiles = certProfiles.filter((p: any) =>
        allowedCertIds.size === 0 || allowedCertIds.has(p.id)
    );

    const selectedSigningProfile = signingProfiles.find((p: any) => p.id === signForm.sshSigningProfileId);
    const selectedCertProfile = certProfiles.find((p: any) => p.id === signForm.sshCertProfileId);

    // Compute the effective max validity from the strictest of the three profiles
    const effectiveMaxValidity = Math.min(
        selectedRequestProfile?.maxValidityHours ?? Infinity,
        selectedSigningProfile?.maxValidityHours ?? Infinity,
        selectedCertProfile?.maxValidityHours ?? Infinity,
    );

    // Auto-select first available when request profile changes
    useEffect(() => {
        if (!signForm.sshRequestProfileId) return;
        const newSigning = filteredSigningProfiles.length > 0 ? filteredSigningProfiles[0].id : '';
        const newCert = filteredCertProfiles.length > 0 ? filteredCertProfiles[0].id : '';
        setSignForm(prev => ({
            ...prev,
            sshSigningProfileId: filteredSigningProfiles.some((p: any) => p.id === prev.sshSigningProfileId) ? prev.sshSigningProfileId : newSigning,
            sshCertProfileId: filteredCertProfiles.some((p: any) => p.id === prev.sshCertProfileId) ? prev.sshCertProfileId : newCert,
        }));
    }, [signForm.sshRequestProfileId, signForm.certType]);

    // Client-side validation against profile constraints
    useEffect(() => {
        if (!showSignForm || !signForm.sshRequestProfileId) { setValidationErrors([]); return; }
        const errors: string[] = [];
        const principals = signForm.principals.split(',').map(s => s.trim()).filter(Boolean);

        // Validity hours
        const hours = parseInt(signForm.validityHours);
        if (signForm.validityHours && hours > 0 && effectiveMaxValidity < Infinity && hours > effectiveMaxValidity) {
            errors.push(`Validity ${hours}h exceeds maximum allowed ${effectiveMaxValidity}h`);
        }

        // Principal count (cert profile)
        if (selectedCertProfile && principals.length > selectedCertProfile.maxPrincipals) {
            errors.push(`Too many ${signForm.certType === 'user' ? 'principals' : 'hostnames'}: ${principals.length} (max ${selectedCertProfile.maxPrincipals})`);
        }

        // Principal pattern validation (cert profile)
        if (selectedCertProfile && principals.length > 0) {
            const patterns = parseJsonArray(selectedCertProfile.allowedPrincipalPatterns);
            if (patterns.length > 0) {
                const regexes = patterns.map((p: string) => { try { return new RegExp(p); } catch { return null; } }).filter(Boolean) as RegExp[];
                for (const principal of principals) {
                    if (!regexes.some(rx => rx.test(principal))) {
                        errors.push(`"${principal}" does not match any allowed principal pattern`);
                    }
                }
            }
        }

        setValidationErrors(errors);
    }, [signForm.principals, signForm.validityHours, selectedCertProfile, selectedSigningProfile, selectedRequestProfile, effectiveMaxValidity, showSignForm]);

    // Profile selection is complete when all three are chosen
    const profilesSelected = !!(signForm.sshRequestProfileId && signForm.sshSigningProfileId && signForm.sshCertProfileId);

    // An empty principal list is the most dangerous value the form can send: OpenSSH treats it as
    // "valid for every principal". It is only accepted behind an explicit opt-in.
    const principalsEmpty = signForm.principals.split(',').map(s => s.trim()).filter(Boolean).length === 0;
    const principalsMissing = principalsEmpty && !signForm.allowAnyPrincipal;

    const handleSign = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!selectedCaKeyId) { showToast('warning', 'Please select a CA key first.'); return; }
        if (validationErrors.length > 0) { showToast('error', 'Fix validation errors before submitting.'); return; }
        if (principalsMissing) { showToast('error', signForm.certType === 'user' ? 'Enter at least one principal, or tick "Allow any principal".' : 'Enter at least one hostname, or tick "Allow any principal".'); return; }
        setSigning(true);
        setSignResult(null);
        try {
            const endpoint = signForm.certType === 'user'
                ? `/api/v1/admin/ssh/ca-keys/${selectedCaKeyId}/certificates/sign-user`
                : `/api/v1/admin/ssh/ca-keys/${selectedCaKeyId}/certificates/sign-host`;

            const body: any = {
                sshSigningProfileId: signForm.sshSigningProfileId,
                sshCertProfileId: signForm.sshCertProfileId,
                publicKey: signForm.publicKey,
                keyId: signForm.identity,
                validityHours: parseInt(signForm.validityHours) || undefined,
            };

            if (signForm.certType === 'user') {
                body.principals = signForm.principals.split(',').map((p: string) => p.trim()).filter(Boolean);
            } else {
                body.hostnames = signForm.principals.split(',').map((p: string) => p.trim()).filter(Boolean);
            }

            const result = await apiPost(endpoint, body);
            setSignResult(result);
            setShowSignForm(false);
            setSignForm({ certType: 'user', sshRequestProfileId: '', sshSigningProfileId: '', sshCertProfileId: '', publicKey: '', identity: '', principals: '', allowAnyPrincipal: false, validityHours: '' });
            onRefresh();
        } catch (err: any) {
            showToast('error', err.message || 'Signing failed');
        } finally {
            setSigning(false);
        }
    };

    // Revoke is a plain endpoint (no step-up), so bulk revoke just loops.
    const performBulkRevoke = async () => {
        if (!confirmRevoke) return;
        if (!selectedCaKeyId) { showToast('warning', 'Please select a CA key first.'); setConfirmRevoke(null); return; }
        setRevoking('bulk');
        let ok = 0, failed = 0;
        try {
            for (const c of confirmRevoke) {
                if (c.isRevoked) continue;
                try { await apiPost(`/api/v1/admin/ssh/ca-keys/${selectedCaKeyId}/certificates/${c.id}/revoke`, {}); ok++; } catch { failed++; }
            }
            if (ok) showToast('success', `Revoked ${ok} certificate${ok !== 1 ? 's' : ''}.`);
            if (failed) showToast('error', `${failed} failed to revoke.`);
            onRefresh();
        } finally {
            setRevoking(null);
            setConfirmRevoke(null);
        }
    };

    const handleDownloadCert = async (cert: any) => {
        try {
            // Route through apiBlob.
            const resp = await apiBlob(`/api/v1/admin/ssh/certificates/${cert.id}/download`);
            const text = await resp.text();
            downloadText(text, `${cert.keyId || cert.id}-cert.pub`);
        } catch (err: any) {
            showToast('error', err.message || 'Failed to download certificate');
        }
    };

    const parsePrincipals = (val: any): string[] => {
        if (Array.isArray(val)) return val;
        if (typeof val === 'string') {
            try { const parsed = JSON.parse(val); if (Array.isArray(parsed)) return parsed; } catch { }
            return val.split(',').map((s: string) => s.trim()).filter(Boolean);
        }
        return [];
    };

    const parseExtensions = (val: any): string[] => {
        if (!val) return [];
        if (Array.isArray(val)) return val;
        if (typeof val === 'string') {
            try { const parsed = JSON.parse(val); if (Array.isArray(parsed)) return parsed; } catch { }
            return [val];
        }
        return [];
    };

    const certIsUser = (c: any) => (c.certificateType || c.type || c.certType || '').toLowerCase().includes('user');

    const columns: DataTableColumn<any>[] = [
        {
            key: 'status', header: 'Status', defaultWidth: 110, truncate: false,
            exportValue: (c) => (c.isRevoked ? 'Revoked' : (certIsUser(c) ? 'User' : 'Host')),
            render: (c) => c.isRevoked ? <StatusBadge status="revoked" label="Revoked" /> : <StatusBadge status={certIsUser(c) ? 'pending' : 'active'} label={certIsUser(c) ? 'User' : 'Host'} />,
        },
        { key: 'keyId', header: 'Key ID', defaultWidth: 180, minWidth: 130, truncate: false, exportValue: (c) => c.keyId || c.identity || '', render: (c) => <span className={`text-sm truncate ${c.isRevoked ? 'text-gray-500 line-through' : 'text-gray-900 dark:text-white'}`}>{c.keyId || c.identity}</span> },
        { key: 'serial', header: 'Serial', defaultWidth: 120, exportValue: (c) => c.serialNumber || c.serial || '', render: (c) => <span className="font-mono text-xs text-gray-600 dark:text-gray-400">#{c.serialNumber || c.serial}</span> },
        { key: 'principals', header: 'Principals', defaultWidth: 200, exportValue: (c) => parsePrincipals(c.principals).join(', '), render: (c) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{parsePrincipals(c.principals).join(', ')}</span> },
        { key: 'validBefore', header: 'Expires', defaultWidth: 160, exportValue: (c) => formatDate(c.validBefore || c.expiresAt), render: (c) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(c.validBefore || c.expiresAt)}</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Download', single: true, onClick: (rows) => handleDownloadCert(rows[0]) },
        { label: 'Revoke', variant: 'danger', enabledFor: (c) => !c.isRevoked, onClick: (rows) => setConfirmRevoke(rows) },
    ];

    const certDrawer = (c: any) => {
        const principals = parsePrincipals(c.principals);
        const extensions = parseExtensions(c.extensions);
        return (
            <div className="text-sm">
                <DetailField label="ID" value={c.id} mono />
                <DetailField label="Serial" value={c.serialNumber || c.serial} mono />
                <DetailField label="Type" value={c.certificateType || c.type || c.certType} />
                <DetailField label="Key ID" value={c.keyId || c.identity} />
                <DetailField label="Principals" value={principals.join(', ')} />
                <DetailField label="Valid After" value={formatDate(c.validAfter || c.issuedAt)} />
                <DetailField label="Valid Before" value={formatDate(c.validBefore || c.expiresAt)} />
                <DetailField label="CA Key ID" value={c.sshCaKeyId} mono />
                {extensions.length > 0 && <DetailField label="Extensions" value={extensions.join(', ')} />}
                <DetailField label="Revoked" value={c.isRevoked ? 'Yes' : 'No'} />
            </div>
        );
    };

    return (
        <div className="space-y-4">
            {/* CA Key Selector */}
            <div className="flex items-center gap-3">
                <label className="text-sm text-gray-600 dark:text-gray-400 font-medium">CA Key:</label>
                <select
                    value={selectedCaKeyId}
                    onChange={(e) => setSelectedCaKeyId(e.target.value)}
                    className="px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                >
                    {caKeys.filter(k => k.isEnabled !== false).length === 0 && <option value="">No CA keys available</option>}
                    {caKeys.filter(k => k.isEnabled !== false).map((k: any) => (
                        <option key={k.id} value={k.id}>{k.name || k.id} ({k.keyType || k.algorithm})</option>
                    ))}
                </select>
            </div>

            <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">SSH Certificates</h2>
                <button
                    onClick={() => { setShowSignForm(!showSignForm); setSignResult(null); }}
                    disabled={!selectedCaKeyId}
                    className="px-4 py-2 text-sm bg-green-600 text-gray-900 dark:text-white rounded hover:bg-green-700 disabled:opacity-50 transition-colors"
                >
                    {showSignForm ? 'Cancel' : 'Sign Key'}
                </button>
            </div>

            {/* Sign Form */}
            {showSignForm && (
                <form onSubmit={handleSign} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                        Sign {signForm.certType === 'user' ? 'User' : 'Host'} Key
                    </h3>

                    {/* Certificate Type */}
                    <div>
                        <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Certificate Type</label>
                        <select
                            value={signForm.certType}
                            onChange={(e) => setSignForm({ ...signForm, certType: e.target.value as 'user' | 'host', sshSigningProfileId: '', sshCertProfileId: '' })}
                            className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                        >
                            <option value="user">User Certificate</option>
                            <option value="host">Host Certificate</option>
                        </select>
                    </div>

                    {/* Step 1: Profile Selection */}
                    <div className="space-y-3">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            <div>
                                <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Request Profile</label>
                                <select
                                    required
                                    value={signForm.sshRequestProfileId}
                                    onChange={(e) => setSignForm({ ...signForm, sshRequestProfileId: e.target.value, sshSigningProfileId: '', sshCertProfileId: '' })}
                                    className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                                >
                                    <option value="">Select request profile...</option>
                                    {requestProfiles.map((p) => (
                                        <option key={p.id} value={p.id}>{p.name}</option>
                                    ))}
                                </select>
                            </div>
                            <div>
                                <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Signing Profile</label>
                                <select
                                    required
                                    disabled={!signForm.sshRequestProfileId}
                                    value={signForm.sshSigningProfileId}
                                    onChange={(e) => setSignForm({ ...signForm, sshSigningProfileId: e.target.value })}
                                    className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 disabled:opacity-50"
                                >
                                    <option value="">Select signing profile...</option>
                                    {filteredSigningProfiles.map((p) => (
                                        <option key={p.id} value={p.id}>{p.name}</option>
                                    ))}
                                </select>
                                {signForm.sshRequestProfileId && filteredSigningProfiles.length === 0 && (
                                    <p className="text-xs text-red-800 dark:text-red-400 mt-1">No {signForm.certType} signing profiles allowed by this request profile</p>
                                )}
                            </div>
                            <div>
                                <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Cert Profile</label>
                                <select
                                    required
                                    disabled={!signForm.sshRequestProfileId}
                                    value={signForm.sshCertProfileId}
                                    onChange={(e) => setSignForm({ ...signForm, sshCertProfileId: e.target.value })}
                                    className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 disabled:opacity-50"
                                >
                                    <option value="">Select cert profile...</option>
                                    {filteredCertProfiles.map((p) => (
                                        <option key={p.id} value={p.id}>{p.name}</option>
                                    ))}
                                </select>
                                {signForm.sshRequestProfileId && filteredCertProfiles.length === 0 && (
                                    <p className="text-xs text-red-800 dark:text-red-400 mt-1">No cert profiles allowed by this request profile</p>
                                )}
                            </div>
                        </div>

                        {/* Profile constraint summary */}
                        {profilesSelected && (
                            <div className="p-2 bg-white dark:bg-gray-950 border border-gray-300 dark:border-gray-700 rounded text-xs text-gray-600 dark:text-gray-400 flex flex-wrap gap-x-4 gap-y-1">
                                <span>Max validity: <span className="text-gray-900 dark:text-white font-medium">{effectiveMaxValidity === Infinity ? 'unlimited' : `${effectiveMaxValidity}h`}</span></span>
                                {selectedCertProfile && <span>Max principals: <span className="text-gray-900 dark:text-white font-medium">{selectedCertProfile.maxPrincipals}</span></span>}
                                {selectedSigningProfile?.forceCommand && <span>Force command: <span className="text-gray-900 dark:text-white font-medium font-mono">{selectedSigningProfile.forceCommand}</span></span>}
                                {selectedCertProfile && parseJsonArray(selectedCertProfile.allowedPrincipalPatterns).length > 0 && (
                                    <span>Principal patterns: <span className="text-gray-900 dark:text-white font-medium font-mono">{parseJsonArray(selectedCertProfile.allowedPrincipalPatterns).join(', ')}</span></span>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Step 2: Certificate Details (disabled until profiles are selected) */}
                    <fieldset disabled={!profilesSelected} className={!profilesSelected ? 'opacity-40' : ''}>
                        <div className="space-y-3">
                            <div>
                                <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Public Key</label>
                                <textarea
                                    required
                                    rows={3}
                                    placeholder="ssh-ed25519 AAAA..."
                                    value={signForm.publicKey}
                                    onChange={(e) => setSignForm({ ...signForm, publicKey: e.target.value })}
                                    className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white font-mono placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500"
                                />
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                                <div>
                                    <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">Identity (Key ID)</label>
                                    <input
                                        type="text"
                                        required
                                        placeholder={signForm.certType === 'user' ? 'username' : 'hostname'}
                                        value={signForm.identity}
                                        onChange={(e) => setSignForm({ ...signForm, identity: e.target.value })}
                                        className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500"
                                    />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">
                                        {signForm.certType === 'user' ? 'Principals' : 'Hostnames'} (comma-separated)
                                    </label>
                                    <input
                                        type="text"
                                        placeholder={signForm.certType === 'user' ? 'root,admin' : 'web01.example.com'}
                                        value={signForm.principals}
                                        onChange={(e) => setSignForm({ ...signForm, principals: e.target.value })}
                                        className={`w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500 ${
                                            validationErrors.some(e => e.includes('principal') || e.includes('hostname')) || principalsMissing ? 'border-red-500' : 'border-gray-300 dark:border-gray-700'
                                        }`}
                                    />
                                    <FieldHint tone="warn">
                                        One or more names this certificate authorises. Leave it blank and OpenSSH treats the certificate as valid for every principal; for a user certificate that is a wildcard. For a host certificate these must match the hostname clients actually type.
                                    </FieldHint>
                                    <label className="mt-2 flex items-start gap-2 text-xs text-gray-700 dark:text-gray-300">
                                        <input
                                            type="checkbox"
                                            checked={signForm.allowAnyPrincipal}
                                            onChange={(e) => setSignForm({ ...signForm, allowAnyPrincipal: e.target.checked })}
                                            className="rounded mt-0.5"
                                        />
                                        <span>Allow any principal (issue with an empty list)</span>
                                    </label>
                                    {signForm.allowAnyPrincipal && (
                                        <FieldHint tone="warn">
                                            {signForm.certType === 'user'
                                                ? 'The certificate will log in as any account on any server that trusts this CA, subject only to the server\'s own AuthorizedPrincipals rules. Use it for break-glass keys, not people.'
                                                : 'Clients will accept this host certificate for any hostname they connect to, so it no longer proves which server they reached.'}
                                        </FieldHint>
                                    )}
                                    {principalsMissing && (
                                        <FieldHint tone="warn">
                                            Enter at least one {signForm.certType === 'user' ? 'principal' : 'hostname'}, or tick the box above to issue a certificate that is valid for every principal.
                                        </FieldHint>
                                    )}
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">
                                        Validity (hours){effectiveMaxValidity < Infinity ? ` (max ${effectiveMaxValidity})` : ''}
                                    </label>
                                    <input
                                        type="text"
                                        inputMode="numeric"
                                        placeholder={effectiveMaxValidity < Infinity ? String(effectiveMaxValidity) : '720'}
                                        value={signForm.validityHours}
                                        onChange={(e) => setSignForm({ ...signForm, validityHours: e.target.value.replace(/\D/g, '') })}
                                        className={`w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500 ${
                                            validationErrors.some(e => e.includes('Validity')) ? 'border-red-500' : 'border-gray-300 dark:border-gray-700'
                                        }`}
                                    />
                                </div>
                            </div>
                        </div>
                    </fieldset>

                    {/* Validation errors */}
                    {validationErrors.length > 0 && (
                        <div className="p-2 bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-700 rounded text-xs text-red-800 dark:text-red-400 space-y-0.5">
                            {validationErrors.map((err, i) => <p key={i}>{err}</p>)}
                        </div>
                    )}

                    <div className="flex gap-2">
                        <button
                            type="submit"
                            disabled={signing || !profilesSelected || validationErrors.length > 0 || principalsMissing}
                            className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                        >
                            {signing ? 'Signing...' : 'Sign Key'}
                        </button>
                        <button
                            type="button"
                            onClick={() => { setShowSignForm(false); setSignResult(null); setValidationErrors([]); setSignForm({ certType: 'user', sshRequestProfileId: '', sshSigningProfileId: '', sshCertProfileId: '', publicKey: '', identity: '', principals: '', allowAnyPrincipal: false, validityHours: '' }); }}
                            className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
                        >
                            Cancel
                        </button>
                    </div>
                </form>
            )}

            {/* Sign Result */}
            {signResult && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-green-300 dark:border-green-700 rounded-lg p-4 space-y-3">
                    <div className="flex items-center gap-2">
                        <span className="text-green-800 dark:text-green-400 font-semibold text-sm">Certificate Signed Successfully</span>
                    </div>
                    <div className="text-xs text-gray-600 dark:text-gray-400 space-y-1">
                        <p><span className="text-gray-700 dark:text-gray-300">Key ID:</span> {signResult.keyId}</p>
                        <p><span className="text-gray-700 dark:text-gray-300">Serial:</span> {signResult.serialNumber}</p>
                        <p><span className="text-gray-700 dark:text-gray-300">Valid:</span> {formatDate(signResult.validAfter)} - {formatDate(signResult.validBefore)}</p>
                    </div>
                    {signResult.signedCertificate && (
                        <>
                            <textarea
                                readOnly
                                rows={3}
                                value={signResult.signedCertificate}
                                className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-xs text-gray-700 dark:text-gray-300 font-mono focus:outline-none"
                            />
                            <button
                                onClick={() => downloadText(signResult.signedCertificate, `${signResult.keyId}-cert.pub`)}
                                className="px-3 py-1.5 text-xs bg-green-700 text-gray-900 dark:text-white rounded hover:bg-green-600 transition-colors"
                            >
                                Download Certificate (-cert.pub)
                            </button>
                        </>
                    )}
                    <p className="text-xs text-gray-600">
                        Save this as <code className="text-blue-800 dark:text-blue-400">~/.ssh/id_ed25519-cert.pub</code> alongside your private key.
                    </p>
                </div>
            )}

            {/* Certificate List */}
            <DataTable<any>
                tableId="ssh-certs"
                title="SSH Certificates"
                rows={certs}
                rowKey={(c) => c.id || c.serial || c.fingerprint}
                loading={loading}
                error={error}
                empty="No SSH certificates issued"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="ssh-certificates"
                renderDrawer={certDrawer}
                drawerTitle={(c) => c.keyId || c.identity || `#${c.serialNumber || c.serial}`}
                detailPath={(c) => `/ssh/certs/${c.id}?caKey=${c.sshCaKeyId || selectedCaKeyId}`}
            />

            <ConfirmModal
                isOpen={!!confirmRevoke}
                title="Revoke SSH Certificates"
                message={confirmRevoke ? (() => {
                    const n = confirmRevoke.filter((c) => !c.isRevoked).length;
                    return `Revoke ${n} certificate${n !== 1 ? 's' : ''}? This cannot be undone.`;
                })() : ''}
                confirmLabel="Revoke"
                confirmClass="bg-red-600 hover:bg-red-700"
                loading={revoking === 'bulk'}
                onConfirm={performBulkRevoke}
                onCancel={() => setConfirmRevoke(null)}
            />
        </div>
    );
};

/* ─── SSH Certificates Page ─── */
const SshCertificates: React.FC = () => {
    const [refreshTrigger, setRefreshTrigger] = useState(0);
    const [caKeys, setCaKeys] = useState<any[]>([]);
    const refresh = () => setRefreshTrigger((t) => t + 1);

    // Load CA keys for the certificate section's CA key selector
    useEffect(() => {
        apiGet<any>('/api/v1/admin/ssh/ca-keys')
            .then((data) => {
                setCaKeys(Array.isArray(data) ? data : (data.items || data.keys || []));
            })
            .catch(() => {});
    }, [refreshTrigger]);

    return (
        <div className="p-6 space-y-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">SSH Certificates</h1>
            <SshCaKeys refreshTrigger={refreshTrigger} onRefresh={refresh} />
            <SshCerts refreshTrigger={refreshTrigger} onRefresh={refresh} caKeys={caKeys} />
        </div>
    );
};

export default SshCertificates;
