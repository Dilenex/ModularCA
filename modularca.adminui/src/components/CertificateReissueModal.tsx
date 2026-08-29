import React, { useState, useEffect } from 'react';
import { apiPostWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { looksLikeHostname } from '@shared/hostname';
import { StepUpOps } from '@shared/generated';
import { inputClass, labelClass } from '@shared/components/forms';

/// Properties for the shared CertificateReissueModal.
export interface CertificateReissueModalProps {
    open: boolean;
    onClose: () => void;
    onSuccess: (message: string) => void;
    cert: {
        id: string;                  // cert Guid
        serialNumber: string;        // for display
        subjectDN: string;           // current full DN — parsed for pre-fill
        sans?: string[];             // current SAN list — pre-fills the SAN textarea
        notBefore?: string;          // current validity start, for reference
        notAfter?: string;           // current validity end, for reference
    } | null;
}

interface SubjectComponents {
    CN: string;
    O: string;
    OU: string;
    L: string;
    ST: string;
    C: string;
}

interface ReissueForm extends SubjectComponents {
    sansText: string;
    notBefore: string;
    notAfter: string;
}

const EMPTY_FORM: ReissueForm = {
    CN: '',
    O: '',
    OU: '',
    L: '',
    ST: '',
    C: '',
    sansText: '',
    notBefore: '',
    notAfter: '',
};

/// Parses a comma-separated subject DN like "CN=foo,O=bar,C=US" into its
/// component pieces. Unknown components are dropped, missing ones are blank.
function parseSubjectDn(dn: string | undefined | null): SubjectComponents {
    const out: SubjectComponents = { CN: '', O: '', OU: '', L: '', ST: '', C: '' };
    if (!dn) return out;
    const parts = dn.split(',').map((p) => p.trim()).filter(Boolean);
    for (const part of parts) {
        const eq = part.indexOf('=');
        if (eq <= 0) continue;
        const key = part.substring(0, eq).trim().toUpperCase();
        const value = part.substring(eq + 1).trim();
        if (key in out) {
            (out as any)[key] = value;
        }
    }
    return out;
}

/// Builds a comma-joined subject DN from the form components.
/// Returns null if every component is blank.
function buildSubjectDn(form: ReissueForm): string | null {
    const order: (keyof SubjectComponents)[] = ['CN', 'O', 'OU', 'L', 'ST', 'C'];
    const parts: string[] = [];
    for (const key of order) {
        const value = form[key].trim();
        if (value) parts.push(`${key}=${value}`);
    }
    if (parts.length === 0) return null;
    return parts.join(',');
}

function formatRefDate(d: string | undefined | null): string {
    if (!d) return '-';
    try {
        return new Date(d).toLocaleString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit',
        });
    } catch {
        return d;
    }
}

/// Modal that lets an admin reissue a certificate. The current cert is
/// revoked (Superseded) and a new one is issued using the same signing
/// profile. All overrides are optional — blank means "keep current".
const CertificateReissueModal: React.FC<CertificateReissueModalProps> = ({ open, onClose, onSuccess, cert }) => {
    const { requireStepUp } = useStepUp();
    const [form, setForm] = useState<ReissueForm>(EMPTY_FORM);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Pre-fill the form whenever the modal opens with a new cert
    useEffect(() => {
        if (!open || !cert) return;
        const parts = parseSubjectDn(cert.subjectDN);
        setForm({
            ...parts,
            sansText: (cert.sans ?? []).join('\n'),
            notBefore: '',
            notAfter: '',
        });
        setError(null);
        setSubmitting(false);
    }, [open, cert]);

    if (!open || !cert) return null;

    const updateField = (field: keyof ReissueForm, value: string) => {
        setForm((prev) => ({ ...prev, [field]: value }));
    };



    const cnValue = form.CN.trim();

    // Entries are "DNS:host" here, but the server also accepts a bare host line, so check both
    // spellings before offering to add what would be a duplicate.
    const cnAlreadyASan = form.sansText
        .split(/\r?\n/)
        .map((l) => l.trim().toLowerCase())
        .some((l) => l === 'dns:' + cnValue.toLowerCase() || l === cnValue.toLowerCase());

    const canAddCnAsSan = looksLikeHostname(cnValue) && !cnAlreadyASan;

    const addCnAsSan = () => {
        if (!canAddCnAsSan) return;
        const kept = form.sansText.split(/\r?\n/).filter((l) => l.trim());
        kept.push('DNS:' + cnValue);
        updateField('sansText', kept.join(String.fromCharCode(10)));
    };

    const handleClose = () => {
        if (submitting) return;
        onClose();
    };

    const handleSubmit = async () => {
        if (!cert) return;
        setSubmitting(true);
        setError(null);
        try {
            const body: any = { serialNumber: cert.serialNumber };
            const newDn = buildSubjectDn(form);
            if (newDn && newDn !== cert.subjectDN) body.newSubjectDn = newDn;
            // Send whenever the list CHANGED, including when it was cleared. This was
            // `if (form.sansText)`, which is falsy for an empty textarea — so emptying the box
            // omitted newSans entirely, the server's `if (newSans != null)` never fired, and the
            // reissued certificate silently kept its original SANs. The operator saw a success
            // toast for a removal that did not happen. An empty array is meaningful here: the
            // server serializes it to "[]", which correctly means "no SANs".
            const originalSans = (cert.sans ?? []).map((s) => s.trim()).filter(Boolean);
            const editedSans = form.sansText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
            const sansChanged =
                editedSans.length !== originalSans.length ||
                editedSans.some((v, i) => v !== originalSans[i]);
            if (sansChanged) body.newSans = editedSans;
            if (form.notBefore) body.notBefore = new Date(form.notBefore).toISOString();
            if (form.notAfter) body.notAfter = new Date(form.notAfter).toISOString();

            const result = await apiPostWithMfa<any>(
                `/api/v1/admin/certificates/serial/${cert.serialNumber}/reissue`,
                body,
                requireStepUp,
                StepUpOps.ReissueCert,
                cert.serialNumber,
            );
            const warnings = result?.warnings as string[] | undefined;
            const msg = result?.message || `Reissued — new serial ${result?.newSerialNumber ?? 'unknown'}`;
            onSuccess(warnings?.length ? `${msg}. Warning: ${warnings.join('; ')}` : msg);
            onClose();
        } catch (err: any) {
            if (err?.message === 'Step-up MFA cancelled') {
                setSubmitting(false);
                return;
            }
            setError(err?.message || 'Reissue failed');
        } finally {
            setSubmitting(false);
        }
    };

    const helperClass = 'text-[11px] text-gray-600 dark:text-gray-500 mt-1';

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/20 dark:bg-black/50"
            onClick={handleClose}
        >
            <div
                className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] flex flex-col"
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header */}
                <div className="px-6 py-4 border-b border-gray-300 dark:border-gray-700 flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Reissue Certificate</h2>
                    <button
                        onClick={handleClose}
                        disabled={submitting}
                        aria-label="Close"
                        className="text-gray-600 hover:text-gray-700 dark:hover:text-gray-300 disabled:opacity-50"
                    >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* Body */}
                <div className="px-6 py-4 space-y-4 overflow-y-auto">
                    {/* Current cert reference */}
                    <div className="bg-gray-50 dark:bg-gray-900/60 border border-gray-300 dark:border-gray-700 rounded p-3 space-y-2">
                        <div>
                            <div className="text-xs text-gray-600 dark:text-gray-400">Current Serial</div>
                            <div className="font-mono text-xs text-gray-800 dark:text-gray-200 break-all">{cert.serialNumber}</div>
                        </div>
                        <div>
                            <div className="text-xs text-gray-600 dark:text-gray-400">Current Subject</div>
                            <div className="text-xs text-gray-800 dark:text-gray-200 break-all">{cert.subjectDN}</div>
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                            <div>
                                <div className="text-xs text-gray-600 dark:text-gray-400">Current Not Before</div>
                                <div className="text-xs text-gray-800 dark:text-gray-200">{formatRefDate(cert.notBefore)}</div>
                            </div>
                            <div>
                                <div className="text-xs text-gray-600 dark:text-gray-400">Current Not After</div>
                                <div className="text-xs text-gray-800 dark:text-gray-200">{formatRefDate(cert.notAfter)}</div>
                            </div>
                        </div>
                    </div>

                    {/* Info banner */}
                    <div className="px-3 py-2 bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-700/50 rounded text-xs text-blue-800 dark:text-blue-300">
                        Reissue marks the current certificate as revoked (reason: Superseded) and issues a new
                        certificate using the same signing profile. Subject DN and SAN changes are validated
                        against the resolved request profile before signing.
                    </div>

                    {/* Subject components */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label htmlFor="reissue-cn" className={labelClass}>Common Name (CN)</label>
                            <input
                                id="reissue-cn"
                                type="text"
                                value={form.CN}
                                onChange={(e) => updateField('CN', e.target.value)}
                                disabled={submitting}
                                className={inputClass}
                            />
                        </div>
                        <div>
                            <label htmlFor="reissue-o" className={labelClass}>Organization (O)</label>
                            <input
                                id="reissue-o"
                                type="text"
                                value={form.O}
                                onChange={(e) => updateField('O', e.target.value)}
                                disabled={submitting}
                                className={inputClass}
                            />
                        </div>
                        <div>
                            <label htmlFor="reissue-ou" className={labelClass}>Organizational Unit (OU)</label>
                            <input
                                id="reissue-ou"
                                type="text"
                                value={form.OU}
                                onChange={(e) => updateField('OU', e.target.value)}
                                disabled={submitting}
                                className={inputClass}
                            />
                        </div>
                        <div>
                            <label htmlFor="reissue-l" className={labelClass}>Locality (L)</label>
                            <input
                                id="reissue-l"
                                type="text"
                                value={form.L}
                                onChange={(e) => updateField('L', e.target.value)}
                                disabled={submitting}
                                className={inputClass}
                            />
                        </div>
                        <div>
                            <label htmlFor="reissue-st" className={labelClass}>State / Province (ST)</label>
                            <input
                                id="reissue-st"
                                type="text"
                                value={form.ST}
                                onChange={(e) => updateField('ST', e.target.value)}
                                disabled={submitting}
                                className={inputClass}
                            />
                        </div>
                        <div>
                            <label htmlFor="reissue-c" className={labelClass}>Country (C)</label>
                            <input
                                id="reissue-c"
                                type="text"
                                value={form.C}
                                onChange={(e) => updateField('C', e.target.value.toUpperCase())}
                                disabled={submitting}
                                maxLength={2}
                                className={inputClass}
                            />
                        </div>
                    </div>

                    {/* SANs */}
                    <div>
                        <label htmlFor="reissue-sans" className={labelClass}>Subject Alternative Names</label>
                        <textarea
                            id="reissue-sans"
                            value={form.sansText}
                            onChange={(e) => updateField('sansText', e.target.value)}
                            disabled={submitting}
                            rows={4}
                            placeholder={'DNS:example.com\nDNS:www.example.com\nIP:10.0.0.1'}
                            className={`${inputClass} resize-none font-mono`}
                        />
                        {canAddCnAsSan && (
                            <div className="mt-2">
                                <button
                                    type="button"
                                    onClick={addCnAsSan}
                                    title={"Add " + cnValue + " as a DNS Subject Alternative Name"}
                                    className="px-3 py-1.5 text-xs text-green-800 dark:text-green-300 border border-green-300 dark:border-green-700 rounded hover:bg-green-900/30 transition-colors"
                                >
                                    + Use CN as DNS SAN
                                    <span className="ml-1.5 font-mono opacity-80">{cnValue}</span>
                                </button>
                                <p className="text-xs text-yellow-800 dark:text-yellow-400 mt-2">
                                    <span className="font-semibold">{cnValue}</span> is not listed as a DNS SAN.
                                    Clients ignore the Common Name for hostname verification, so this
                                    certificate would not validate for that name.
                                </p>
                            </div>
                        )}
                        <div className={helperClass}>
                            One per line. Prefix with <span className="font-mono">DNS:</span>, <span className="font-mono">IP:</span>,{' '}
                            <span className="font-mono">email:</span>, or <span className="font-mono">URI:</span> to indicate the SAN type.
                        </div>
                    </div>

                    {/* Validity overrides */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label htmlFor="reissue-not-before" className={labelClass}>Valid From (notBefore)</label>
                            <input
                                id="reissue-not-before"
                                type="datetime-local"
                                value={form.notBefore}
                                onChange={(e) => updateField('notBefore', e.target.value)}
                                disabled={submitting}
                                className={inputClass}
                            />
                            <div className={helperClass}>Leave blank to use the current time.</div>
                        </div>
                        <div>
                            <label htmlFor="reissue-not-after" className={labelClass}>Valid To (notAfter)</label>
                            <input
                                id="reissue-not-after"
                                type="datetime-local"
                                value={form.notAfter}
                                onChange={(e) => updateField('notAfter', e.target.value)}
                                disabled={submitting}
                                className={inputClass}
                            />
                            <div className={helperClass}>Leave blank to use the signing profile's default (recommended).</div>
                        </div>
                    </div>

                    {/* Error */}
                    {error && (
                        <div className="px-3 py-2 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700/50 rounded text-sm text-red-800 dark:text-red-300">
                            {error}
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="px-6 py-4 border-t border-gray-300 dark:border-gray-700 flex justify-end gap-3">
                    <button
                        onClick={handleClose}
                        disabled={submitting}
                        className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleSubmit}
                        disabled={submitting}
                        className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors disabled:opacity-50 flex items-center gap-2"
                    >
                        {submitting && (
                            <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                            </svg>
                        )}
                        {submitting ? 'Reissuing...' : 'Reissue'}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default CertificateReissueModal;
