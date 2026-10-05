import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { isApiError } from '@shared-auth/api/problem';
import { Chevron } from '@shared/components/Chevron';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { scopeLabel } from '../scope';
import { useAuth } from '../context/AuthContext';
import { can, canAtSpace, consoleCas, spacesOf } from '../authz';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { caKey } from './CaDetail';
import { Capabilities, StepUpOps } from '@shared/generated';
import { FieldHint, inputClass, labelClass } from '@shared/components/forms';
import { CEREMONY_UNKNOWN_HINT, INSTANCE_SCOPE, ceremonyRequiredFor, createCaButtonLabel } from './caCreation';
import { type CeremonyRefusal, readCeremonyRefusal } from './ceremonyRefusal';
import { CeremonyRefusalNotice } from '../components/CeremonyRefusalNotice';
import { NameConstraintsEditor, type NameConstraintsValue } from '@shared/components/NameConstraintsEditor';
import { nameConstraintRowsInvalid, nameConstraintRowsToList } from '@shared/generalNames';

/** The CA list's space column was keyed 'tenant' before 0.4.0; a stored layout carries over. Remove in 0.5. */
const RENAMED_CA_COLUMNS = { tenant: 'space' };

/** ML-DSA and SLH-DSA: the FIPS 204 / FIPS 205 post-quantum signature schemes. */
const isPostQuantum = (alg: string) => alg.startsWith('ML-DSA') || alg.startsWith('SLH-DSA');

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function caTypeBadge(ca: any): { status: 'active' | 'pending' | 'disabled'; label: string } {
    const t = (ca.type || ca.caType || '').toLowerCase();
    if (t.includes('root')) return { status: 'active', label: 'Root' };
    if (t.includes('intermediate')) return { status: 'pending', label: 'Intermediate' };
    return { status: 'disabled', label: 'Issuing' };
}

/* read-only drawer for a CA row */
const CaDrawer: React.FC<{ ca: any }> = ({ ca }) => {
    const cert = ca.certificate;
    return (
        <div className="text-sm">
            <DetailField label="Name" value={ca.name || ca.subjectDN} />
            <DetailField label="Label" value={ca.label} mono />
            <DetailField label="Type" value={caTypeBadge(ca).label} />
            <DetailField label="Status" value={ca.isEnabled ? 'Enabled' : 'Disabled'} />
            {ca.spaceName && <DetailField label="Space" value={ca.spaceName} />}
            <DetailField label="Default" value={ca.isDefault ? 'Yes' : 'No'} />
            {cert && <DetailField label="Serial" value={cert.serialNumber} mono />}
            {cert && <DetailField label="Not After" value={formatDate(cert.notAfter)} />}
            <p className="text-[11px] text-ink-muted pt-3">Open the full page for certificate, protocol and service details.</p>
        </div>
    );
};

const CaManagement: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    // CA List state
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    // Space state. `adminSpaces` is null until the system-admin space list answers, and stays
    // null when it is forbidden; the choices then come from the caller's own capabilities.
    const [adminSpaces, setAdminSpaces] = useState<any[] | null>(null);
    const [spacesError, setSpacesError] = useState<NoticeInput | null>(null);
    const [instanceCeremony, setInstanceCeremony] = useState<boolean | null>(null);
    const [formSpace, setFormSpace] = useState('');

    // Create CA form state
    const [createExpanded, setCreateExpanded] = useState(false);
    const [formCaType, setFormCaType] = useState<'root' | 'intermediate'>('intermediate');
    const [formCN, setFormCN] = useState('');
    const [formOrg, setFormOrg] = useState('');
    const [formOU, setFormOU] = useState('');
    const [formL, setFormL] = useState('');
    const [formST, setFormST] = useState('');
    const [formC, setFormC] = useState('');
    const [formKeyAlg, setFormKeyAlg] = useState('ECDSA');
    const [formKeySize, setFormKeySize] = useState('384');
    const [formValidityYears, setFormValidityYears] = useState('10');
    const [formParentCa, setFormParentCa] = useState('');
    const [formLabel, setFormLabel] = useState('');
    const [formCertProfile, setFormCertProfile] = useState('');
    const [caCertProfiles, setCaCertProfiles] = useState<any[]>([]);
    const [formPublicBaseUrl, setFormPublicBaseUrl] = useState('');
    const [createLoading, setCreateLoading] = useState(false);
    const [createError, setCreateError] = useState<NoticeInput | null>(null);
    // The create was refused because nobody else could approve its ceremony; shown with next steps.
    const [createRefusal, setCreateRefusal] = useState<CeremonyRefusal | null>(null);
    const [createSuccess, setCreateSuccess] = useState<string | null>(null);

    // Name constraints, as typed rows; sent as List<string> of TYPE:value.
    const [nameConstraints, setNameConstraints] = useState<NameConstraintsValue>({ permitted: [], excluded: [] });
    const nameConstraintsInvalid = nameConstraintRowsInvalid(nameConstraints.permitted) || nameConstraintRowsInvalid(nameConstraints.excluded);
    const permittedList = nameConstraintRowsToList(nameConstraints.permitted);
    const excludedList = nameConstraintRowsToList(nameConstraints.excluded);

    const flattenCas = (cas: any[]): any[] => {
        const result: any[] = [];
        for (const ca of cas) {
            result.push(ca);
            if (ca.children && ca.children.length > 0) {
                result.push(...flattenCas(ca.children));
            }
        }
        return result;
    };

    const { caId: scopeCaId, spaceId: scopeSpaceId, inScope, scope } = useScope();
    const { capabilities } = useAuth();
    const isSystemAdmin = can(capabilities, Capabilities.SystemManage);
    /** System-scoped ca.manage may create in any space and under any parent, as the server allows. */
    const managesAllSpaces = isSystemAdmin || can(capabilities, Capabilities.CaManage);
    /**
     * The spaces the caller may create a CA in. The space list endpoint is system-admin only, so
     * a system operator's and a space administrator's choices come from their capabilities.
     */
    const creatableSpaces: Array<{ id: string; name: string }> = adminSpaces
        ? adminSpaces.filter(t => t.isEnabled)
        : spacesOf(capabilities).filter(t => canAtSpace(capabilities, Capabilities.CaManage, t.id));
    const canCreateCa = managesAllSpaces || creatableSpaces.length > 0;
    const targetCeremony = ceremonyRequiredFor(formSpace, { instance: instanceCeremony, spaces: adminSpaces ?? [] });

    /** The subtree rooted at the scoped CA, so a single-CA scope shows that CA and what it issued. */
    const subtreeOf = (list: any[], id: string): any | null => {
        for (const ca of list) {
            if ((ca.id || ca.caId) === id) return ca;
            const found = ca.children?.length ? subtreeOf(ca.children, id) : null;
            if (found) return found;
        }
        return null;
    };

    const loadAuthorities = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/authorities/hierarchy')
            .then((data) => {
                const all = Array.isArray(data) ? data : (data.items || data.authorities || []);
                const scoped = scopeCaId ? subtreeOf(all, scopeCaId) : null;
                const items = scopeCaId
                    ? (scoped ? [scoped] : [])
                    : scopeSpaceId ? all.filter((root: any) => inScope(root.id || root.caId)) : all;
                setAuthorities(items);
                const flat = flattenCas(items);
                if (flat.length > 0 && !formParentCa) {
                    setFormParentCa(flat[0].id || flat[0].certificateId || flat[0].name || '');
                }
                setLoading(false);
            })
            .catch((err) => {
                // A space administrator whose space has no CA yet is refused the list (it needs a
                // CA to be scoped to); there is nothing to list, and the create panel still works.
                if (isApiError(err) && err.status === 403 && consoleCas(capabilities).length === 0) setAuthorities([]);
                else setError(errorNotice(err, 'Failed to load authorities'));
                setLoading(false);
            });
    };

    useEffect(() => {
        if (!managesAllSpaces) return;
        let cancelled = false;
        setSpacesError(null);
        apiGet<any>('/api/v1/admin/spaces')
            .then(data => { if (!cancelled) setAdminSpaces(Array.isArray(data) ? data : data.items || []); })
            .catch((err) => {
                if (cancelled) return;
                setAdminSpaces(null);
                if (!(isApiError(err) && err.status === 403)) setSpacesError(errorNotice(err, 'Failed to load spaces'));
            });
        // The instance's ceremony policy only labels the button; unknown falls back to a hint.
        apiGet<any>('/api/v1/admin/security-policy')
            .then(p => { if (!cancelled) setInstanceCeremony(typeof p?.requireKeyCeremony === 'boolean' ? p.requireKeyCeremony : null); })
            .catch(() => { if (!cancelled) setInstanceCeremony(null); });
        return () => { cancelled = true; };
    }, [managesAllSpaces]);

    // A space administrator of one space has nothing to choose; a system administrator picks.
    useEffect(() => {
        if (!formSpace && creatableSpaces.length === 1) setFormSpace(creatableSpaces[0].id);
    }, [formSpace, creatableSpaces.length]); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        loadAuthorities();
        apiGet<any>('/api/v1/admin/cert-profiles?isCaProfile=true')
            .then(data => {
                const items = Array.isArray(data) ? data : (data.items || []);
                setCaCertProfiles(items);
                if (items.length > 0 && !formCertProfile) setFormCertProfile(items[0].id);
            })
            .catch(() => {});
    }, [scopeCaId, scopeSpaceId]); // eslint-disable-line react-hooks/exhaustive-deps

    const allCasFlat = flattenCas(authorities);
    /**
     * Parents the caller may sign under: any CA for a system-scoped holder, otherwise the chosen
     * space's own CAs and any CA they hold ca.manage on. Mirrors CaCreationAccess on the server.
     */
    const parentKey = (ca: any) => ca.id || ca.certificateId || ca.name;
    const parentCandidates = allCasFlat.filter((ca) =>
        managesAllSpaces || (!!formSpace && ca.spaceId === formSpace) || can(capabilities, Capabilities.CaManage, ca.id));

    useEffect(() => {
        if (!parentCandidates.some((ca) => parentKey(ca) === formParentCa)) {
            setFormParentCa(parentCandidates[0] ? parentKey(parentCandidates[0]) : '');
        }
    }, [formSpace, parentCandidates.length]); // eslint-disable-line react-hooks/exhaustive-deps

    /**
     * The chosen parent's remaining life in years, so the validity field can warn before the
     * server truncates or rejects a child that would outlive its issuer. `null` when no parent
     * applies (a root) or the parent carries no expiry we can read.
     */
    const selectedParent = formCaType === 'intermediate' ? parentCandidates.find((ca) => parentKey(ca) === formParentCa) : undefined;
    const parentNotAfter: string | undefined = selectedParent?.certificate?.notAfter || selectedParent?.notAfter;
    const parentYearsLeft: number | null = parentNotAfter && !Number.isNaN(new Date(parentNotAfter).getTime())
        ? (new Date(parentNotAfter).getTime() - Date.now()) / (365.25 * 24 * 60 * 60 * 1000)
        : null;
    const requestedYears = parseInt(formValidityYears, 10);
    const outlivesParent = parentYearsLeft !== null && !Number.isNaN(requestedYears) && requestedYears > parentYearsLeft;

    const handleCreateCa = async () => {
        if (!formSpace) {
            setCreateError('Please select a space.');
            return;
        }
        if (!formCN.trim()) {
            setCreateError('Common Name is required.');
            return;
        }
        if (formCaType === 'intermediate' && !formParentCa) {
            setCreateError('Parent CA is required for intermediate CAs.');
            return;
        }
        setCreateLoading(true);
        setCreateError(null);
        setCreateRefusal(null);
        setCreateSuccess(null);

        try {
            const endpoint = formCaType === 'root'
                ? '/api/v1/admin/authorities/create-root'
                : '/api/v1/admin/authorities/create-intermediate';

            // The server refuses a create that names no scope: a space, or the instance explicitly.
            const body: any = {
                ...(formSpace === INSTANCE_SCOPE ? { scope: 'instance' } : { spaceId: formSpace }),
                subjectCN: formCN,
                subjectO: formOrg || undefined,
                subjectOU: formOU || undefined,
                subjectL: formL || undefined,
                subjectST: formST || undefined,
                subjectC: formC || undefined,
                keyAlgorithm: formKeyAlg,
                keySize: parseInt(formKeySize, 10),
                validityYears: parseInt(formValidityYears, 10),
                label: formLabel || undefined,
                certProfileId: formCertProfile || undefined,
                publicBaseUrl: formPublicBaseUrl || undefined,
                nameConstraintsPermitted: permittedList.length > 0 ? permittedList : null,
                nameConstraintsExcluded: excludedList.length > 0 ? excludedList : null,
            };

            if (formCaType === 'intermediate') {
                body.parentCaId = formParentCa;
            }

            const result = await apiPostWithMfa<any>(endpoint, body, requireStepUp, StepUpOps.CreateCa);

            if (result?.requiresCeremony) {
                showToast('info', result.message || 'A key ceremony has been created and requires approval before execution.');
                setCreateSuccess(result.message || `Key ceremony created. ${result.requiredApprovals || 0} approval(s) required. View it in Key Ceremonies.`);
                // Don't clear the form — user may want to review what was submitted
                return;
            }

            setCreateSuccess(`${formCaType === 'root' ? 'Root' : 'Intermediate'} CA created successfully. ${result.message || ''}`);
            setFormCN('');
            setFormLabel('');
            setFormOrg('');
            setFormOU('');
            setFormL('');
            setFormST('');
            setFormC('');
            setNameConstraints({ permitted: [], excluded: [] });
            loadAuthorities();
        } catch (err: any) {
            // Nobody else could approve the ceremony: say so here, with the way out.
            const refusal = readCeremonyRefusal(err);
            if (refusal) setCreateRefusal(refusal);
            else setCreateError(errorNotice(err, 'Failed to create CA'));
        } finally {
            setCreateLoading(false);
        }
    };


    const caColumns: DataTableColumn<any>[] = [
        { key: 'type', header: 'Type', defaultWidth: 130, truncate: false, exportValue: (ca) => caTypeBadge(ca).label, render: (ca) => { const b = caTypeBadge(ca); return <StatusBadge status={b.status} label={b.label} />; } },
        { key: 'name', header: 'Name', defaultWidth: 240, minWidth: 160, truncate: false, exportValue: (ca) => ca.name || ca.subjectDN, render: (ca) => <span className="text-ink truncate">{ca.name || ca.subjectDN}</span> },
        { key: 'space', header: 'Space', defaultWidth: 140, exportValue: (ca) => ca.spaceName || '', render: (ca) => <span className="text-xs text-ink-muted truncate">{ca.spaceName || '-'}</span> },
        // Wire name is `isEnabled` (AdminCaController projects ca.IsEnabled). Reading `ca.enabled`
        // meant `undefined !== false` — every CA, including disabled ones, rendered as Enabled.
        { key: 'status', header: 'Status', defaultWidth: 110, truncate: false, exportValue: (ca) => (ca.isEnabled ? 'Enabled' : 'Disabled'), render: (ca) => <StatusBadge status={ca.isEnabled ? 'enabled' : 'disabled'} label={ca.isEnabled ? 'Enabled' : 'Disabled'} /> },
        { key: 'children', header: 'Children', defaultWidth: 90, exportValue: (ca) => (ca.children?.length || 0), render: (ca) => <span className="text-xs text-ink-muted">{ca.children?.length || 0}</span> },
        { key: 'expires', header: 'Expires', defaultWidth: 160, exportValue: (ca) => formatDate(ca.certificate?.notAfter || ca.notAfter), render: (ca) => <span className="text-xs text-ink-muted">{formatDate(ca.certificate?.notAfter || ca.notAfter)}</span> },
    ];

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">CA Management</h1>

            {/* Section 1: CA List */}
            <DataTable<any>
                tableId="ca-list"
                renamedColumns={RENAMED_CA_COLUMNS}
                title="Certificate Authorities"
                rows={allCasFlat}
                rowKey={caKey}
                loading={loading}
                error={error}
                empty={consoleCas(capabilities).length === 0 && canCreateCa
                    ? 'No certificate authorities yet. Create the first one under Create Certificate Authority below.'
                    : scopeCaId || scopeSpaceId ? `No certificate authorities in ${scopeLabel(scope)}. Change the scope in the sidebar to see others.` : 'No certificate authorities found'}
                columns={caColumns}
                selectable
                exportFileName="certificate-authorities"
                renderDrawer={(ca) => <CaDrawer ca={ca} />}
                drawerTitle={(ca) => ca.name || ca.subjectDN}
                detailPath={(ca) => `/authorities/manage/${encodeURIComponent(caKey(ca))}`}
            />

            {/* Section 2: Create Intermediate CA */}
            {canCreateCa && (
            <div className="bg-raised border border-line rounded-lg overflow-hidden">
                <button
                    onClick={() => setCreateExpanded(!createExpanded)}
                    className="w-full px-4 py-3 flex items-center gap-2 text-left hover:bg-hover bg-sunken transition-colors"
                >
                    <span className="text-ink-muted text-xs"><Chevron open={createExpanded} className="w-3 h-3" /></span>
                    <h3 className="text-sm font-semibold text-ink">Create Certificate Authority</h3>
                </button>
                {createExpanded && (
                    <div className="p-4 border-t border-line space-y-4">
                        {spacesError && <InlineNotice notice={spacesError} />}
                        {/* Space Selector */}
                        <div>
                            <label className={labelClass}>Space *</label>
                            <select value={formSpace} onChange={(e) => setFormSpace(e.target.value)} className={inputClass}>
                                <option value="">-- Select Space --</option>
                                {managesAllSpaces && <option value={INSTANCE_SCOPE}>Instance (no space)</option>}
                                {creatableSpaces.map(t => (
                                    <option key={t.id} value={t.id}>{t.name}</option>
                                ))}
                            </select>
                        </div>

                        {/* CA Type Toggle */}
                        <div className="flex gap-2">
                            {isSystemAdmin && (
                            <button
                                onClick={() => { setFormCaType('root'); setFormValidityYears('25'); }}
                                className={`px-4 py-1.5 text-xs font-semibold rounded transition-colors ${formCaType === 'root' ? 'bg-accent text-on-accent' : 'bg-sunken text-ink-muted hover:bg-hover'}`}
                            >
                                Root CA
                            </button>
                            )}
                            <button
                                onClick={() => { setFormCaType('intermediate'); setFormValidityYears('10'); }}
                                className={`px-4 py-1.5 text-xs font-semibold rounded transition-colors ${formCaType === 'intermediate' ? 'bg-accent text-on-accent' : 'bg-sunken text-ink-muted hover:bg-hover'}`}
                            >
                                Intermediate CA
                            </button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            <div>
                                <label className={labelClass}>Common Name *</label>
                                <input type="text" value={formCN} onChange={(e) => setFormCN(e.target.value)} placeholder={formCaType === 'root' ? 'My Root CA' : 'My Intermediate CA'} className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>Organization</label>
                                <input type="text" value={formOrg} onChange={(e) => setFormOrg(e.target.value)} placeholder="Acme Corp" className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>Organizational Unit</label>
                                <input type="text" value={formOU} onChange={(e) => setFormOU(e.target.value)} placeholder="IT Security" className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>Locality</label>
                                <input type="text" value={formL} onChange={(e) => setFormL(e.target.value)} placeholder="San Francisco" className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>State</label>
                                <input type="text" value={formST} onChange={(e) => setFormST(e.target.value)} placeholder="California" className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>Country</label>
                                <input type="text" value={formC} onChange={(e) => setFormC(e.target.value)} placeholder="US" maxLength={2} className={inputClass} />
                            </div>
                            <div>
                                <label className={labelClass}>Key Algorithm</label>
                                <select value={formKeyAlg} onChange={(e) => setFormKeyAlg(e.target.value)} className={inputClass}>
                                    <option value="RSA">RSA</option>
                                    <option value="ECDSA">ECDSA</option>
                                    <option value="Ed25519">Ed25519</option>
                                    <option value="Ed448">Ed448</option>
                                    <option value="ML-DSA-44">ML-DSA-44</option>
                                    <option value="ML-DSA-65">ML-DSA-65</option>
                                    <option value="ML-DSA-87">ML-DSA-87</option>
                                    <option value="SLH-DSA-SHA2-128F">SLH-DSA-SHA2-128F</option>
                                </select>
                                <FieldHint tone={isPostQuantum(formKeyAlg) ? 'warn' : 'muted'}>
                                    {isPostQuantum(formKeyAlg)
                                        ? 'ML-DSA and SLH-DSA are post-quantum signature schemes. Almost nothing validates them yet: browsers, operating-system trust stores, TLS stacks and most PKI tooling will reject or fail to parse certificates this CA signs. Use them for a lab or a dedicated PQ hierarchy, not for a CA anything in production has to trust.'
                                        : 'RSA and ECDSA are validated everywhere; Ed25519 and Ed448 by most current software. ML-DSA and SLH-DSA are post-quantum and almost nothing validates them yet.'}
                                </FieldHint>
                            </div>
                            {formKeyAlg !== 'Ed25519' && formKeyAlg !== 'Ed448' && !formKeyAlg.startsWith('ML-DSA') && !formKeyAlg.startsWith('SLH-DSA') && (
                            <div>
                                <label className={labelClass}>Key Size</label>
                                <select value={formKeySize} onChange={(e) => setFormKeySize(e.target.value)} className={inputClass}>
                                    {formKeyAlg === 'RSA' ? (
                                        <>
                                            <option value="2048">2048 bits</option>
                                            <option value="3072">3072 bits</option>
                                            <option value="4096">4096 bits</option>
                                            <option value="7680">7680 bits (high compute)</option>
                                            <option value="8192">8192 bits (high compute)</option>
                                        </>
                                    ) : (
                                        <>
                                            <option value="256">P-256</option>
                                            <option value="384">P-384</option>
                                            <option value="521">P-521</option>
                                        </>
                                    )}
                                </select>
                                {formKeyAlg === 'RSA' && (formKeySize === '7680' || formKeySize === '8192') && (
                                    <p className="text-xs text-warn mt-1">
                                        ⚠ High-compute RSA — key generation may take 30+ seconds.
                                    </p>
                                )}
                            </div>
                            )}
                            <div>
                                <label className={labelClass}>Validity (Years)</label>
                                <input type="text" inputMode="numeric" value={formValidityYears} onChange={(e) => setFormValidityYears(e.target.value.replace(/\D/g, ''))} className={inputClass} aria-describedby="ca-validity-hint" />
                                {outlivesParent && parentNotAfter ? (
                                    <FieldHint id="ca-validity-hint" tone="warn">
                                        Longer than the parent has left: {selectedParent?.name || selectedParent?.subjectDN || 'the parent CA'} expires {formatDate(parentNotAfter)}, about {parentYearsLeft!.toFixed(1)} years from now. A CA certificate cannot be trusted past its issuer's expiry, so the effective life would be capped there (or the request refused). Shorten the validity or renew the parent first.
                                    </FieldHint>
                                ) : formCaType === 'intermediate' && parentNotAfter ? (
                                    <FieldHint id="ca-validity-hint">Parent expires {formatDate(parentNotAfter)}; this CA must not outlive it.</FieldHint>
                                ) : null}
                            </div>
                            <div>
                                <label className={labelClass}>Label (optional, auto-generated from CN if empty)</label>
                                <input type="text" value={formLabel} onChange={(e) => setFormLabel(e.target.value)} placeholder="my-intermediate-ca" className={inputClass} />
                            </div>
                            {formCaType === 'intermediate' && (
                                <div>
                                    <label className={labelClass}>Parent CA *</label>
                                    <select value={formParentCa} onChange={(e) => setFormParentCa(e.target.value)} className={inputClass}>
                                        {parentCandidates.length === 0 && <option value="">{formSpace ? 'No CA you may sign under in this space' : 'Select a space first'}</option>}
                                        {parentCandidates.map((ca) => {
                                            const id = parentKey(ca);
                                            return (
                                                <option key={id} value={id}>
                                                    {ca.name || ca.subjectDN}
                                                </option>
                                            );
                                        })}
                                    </select>
                                </div>
                            )}
                            <div>
                                <label className={labelClass}>CA Certificate Profile</label>
                                <select value={formCertProfile} onChange={(e) => setFormCertProfile(e.target.value)} className={inputClass}>
                                    {caCertProfiles.length === 0 && <option value="">No CA profiles available</option>}
                                    {caCertProfiles.map((p) => (
                                        <option key={p.id} value={p.id}>{p.name}</option>
                                    ))}
                                </select>
                            </div>
                        </div>

                        {/* Public Base URL — CDP/OCSP/AIA endpoints are auto-generated from this */}
                        <div className="border-t border-line pt-4 mt-2">
                            <span className="text-xs font-semibold text-ink-muted">Public Base URL</span>
                            <p className="mt-1 text-xs text-ink-muted">
                                The public host clients will use to fetch CRLs, OCSP responses, and the CA certificate (e.g.
                                <code className="mono"> http://path2.ca.example.com</code>). The program auto-appends the
                                standard short-URL paths at cert-build time to produce the CDP
                                (<code className="mono">/crl/{'{label}'}</code>), OCSP (<code className="mono">/ocsp</code>),
                                and AIA (<code className="mono">/ca/{'{label}'}</code>) extensions. Must be plain HTTP so
                                clients can fetch without a chicken-and-egg TLS validation problem. Leave empty to issue
                                certs without CDP/AIA extensions until a base URL is set later.
                            </p>
                            <div className="mt-2">
                                <label className={labelClass}>Public Base URL</label>
                                <input type="text" value={formPublicBaseUrl} onChange={(e) => setFormPublicBaseUrl(e.target.value)} placeholder="http://path2.ca.example.com" className={inputClass} />
                            </div>
                        </div>

                        {/* Name Constraints: baked into the CA cert's NameConstraints extension and copied onto
                            the per-CA signing profile. The server checks them the same way before any ceremony. */}
                        <div className="border-t border-line pt-4 mt-2">
                            <span className="text-xs font-semibold text-ink-muted">Name Constraints</span>
                            <p className="mt-1 mb-2 text-xs text-ink-muted">
                                Restricts the names the new CA, and every CA below it, may issue for.
                            </p>
                            <NameConstraintsEditor idPrefix="create-ca-nc" permitted={nameConstraints.permitted} excluded={nameConstraints.excluded}
                                onChange={setNameConstraints} disabled={createLoading} />
                        </div>

                        <div className="flex items-center gap-4 flex-wrap">
                            <button
                                onClick={handleCreateCa}
                                disabled={createLoading || !formCN.trim() || !formSpace || nameConstraintsInvalid}
                                className="px-6 py-2 text-sm font-semibold bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                            >
                                {createCaButtonLabel(formCaType, targetCeremony, createLoading)}
                            </button>
                            {formSpace && targetCeremony === null && <FieldHint>{CEREMONY_UNKNOWN_HINT}</FieldHint>}
                            {nameConstraintsInvalid && <FieldHint tone="warn">Fix the name constraints marked above to continue.</FieldHint>}
                        </div>

                        {createRefusal && <CeremonyRefusalNotice refusal={createRefusal} />}
                        {createError && (
                            <div className="bg-crit-soft border border-crit/40 rounded p-3">
                                <InlineNotice notice={createError} variant="line" />
                            </div>
                        )}
                        {createSuccess && (
                            <div className="bg-ok-soft border border-ok/40 rounded p-3">
                                <p className="text-sm text-ok">{createSuccess}</p>
                            </div>
                        )}
                    </div>
                )}
            </div>
            )}

        </div>
    );
};

export default CaManagement;
