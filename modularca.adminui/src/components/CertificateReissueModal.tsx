import React, { useState, useEffect } from 'react';
import { apiPostWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { looksLikeHostname } from '@shared/hostname';
import { StepUpOps } from '@shared/generated';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { FieldNotices, hasFieldNotice } from '@shared/components/FieldNotice';
import {
    mergeNotices, unclaimedNotices, worstSeverity,
    type Notice, type NoticeInput, type NoticeSeverity,
} from '@shared/notifications/notice';
import { readDiagnostics } from '@shared-auth/api/problem';
import { diagnosticNotices, errorNotices } from '@shared-auth/api/notices';

/**
 * The names each control answers to.
 *
 * Three vocabularies meet on this form. The inputs are named after the X.509 fields they set
 * (`notBefore`, `notAfter`); a diagnostic from issuance calls the same two `validFrom` and
 * `validTo`; model state names them after the request DTO's properties, and a profile refusal
 * names them in prose. Listing the spellings next to the control is the only place that knows all
 * three — see `fieldMatches`, which does the comparing.
 */
const NOT_BEFORE_FIELDS = ['notBefore', 'validFrom'];
const NOT_AFTER_FIELDS = ['notAfter', 'validTo'];
const SUBJECT_FIELDS = ['newSubjectDn', 'subjectDn', 'subject', 'commonName', 'CN'];
const SAN_FIELDS = ['newSans', 'sans', 'subjectAlternativeNames'];

/** Every field this form places inline. Anything else has to fall back to the summary banner. */
const INLINE_FIELDS = [...NOT_BEFORE_FIELDS, ...NOT_AFTER_FIELDS, ...SUBJECT_FIELDS, ...SAN_FIELDS];

/// Properties for the shared CertificateReissueModal.
export interface CertificateReissueModalProps {
    open: boolean;
    onClose: () => void;
    /**
     * Reports the outcome to the host page, which toasts it.
     *
     * `severity` is second so the existing `(msg) => showToast('success', msg)` handlers keep
     * compiling, but a reissue is not always a success: the certificate can come back without the
     * extended key usages that were asked for, and announcing that in a green toast is how the
     * operator learns to ignore green toasts.
     */
    onSuccess: (message: NoticeInput, severity?: NoticeSeverity) => void;
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
    // The refusal, split into the messages that belong to a control and the ones that do not,
    // rather than the single sentence this used to keep. A rejected notAfter now appears under the
    // Valid To box instead of only in a toast the operator has to look away from the form to read.
    const [notices, setNotices] = useState<Notice[]>([]);

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
        setNotices([]);
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

    // Both overrides are optional, but when both are given the window must run forwards; the
    // server refuses an inverted one, so refuse it here before the step-up prompt is spent on it.
    const validityInverted = !!(form.notBefore && form.notAfter && form.notBefore >= form.notAfter);

    const handleSubmit = async () => {
        if (!cert) return;
        if (validityInverted) return;
        setSubmitting(true);
        setNotices([]);
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
            const advisories = diagnosticNotices(readDiagnostics(result));
            const headline = result?.message || `Reissued — new serial ${result?.newSerialNumber ?? 'unknown'}`;
            // The certificate exists either way, so the modal closes either way — but a diagnostic
            // decides the severity, and its code travels with it so the toast can offer it for
            // copying instead of burying it in a sentence.
            onSuccess(mergeNotices(headline, advisories), worstSeverity(advisories, 'success'));
            onClose();
        } catch (err: any) {
            if (err?.message === 'Step-up MFA cancelled') {
                setSubmitting(false);
                return;
            }
            setNotices(errorNotices(err));
        } finally {
            setSubmitting(false);
        }
    };

    const helperClass = 'text-[11px] text-gray-600 dark:text-gray-500 mt-1';

    // A control that carries a message is marked invalid and points at it, so a screen reader
    // announces the two together; `undefined` rather than a dangling id when there is no message.
    const describedBy = (id: string, fields: string[]) =>
        hasFieldNotice(notices, fields) ? id : undefined;
    const invalidClass = (fields: string[]) =>
        hasFieldNotice(notices, fields) ? ' border-red-500 dark:border-red-500' : '';

    // Whatever no control claimed: the explanation itself, plus any field the server named that
    // this form has no box for. Dropping those would reintroduce the bug this is fixing.
    const bannerNotices = unclaimedNotices(notices, INLINE_FIELDS);

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
                                aria-invalid={hasFieldNotice(notices, SUBJECT_FIELDS)}
                                aria-describedby={describedBy('reissue-cn-notice', SUBJECT_FIELDS)}
                                className={inputClass + invalidClass(SUBJECT_FIELDS)}
                            />
                            <FieldNotices id="reissue-cn-notice" notices={notices} field={SUBJECT_FIELDS} />
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
                            aria-invalid={hasFieldNotice(notices, SAN_FIELDS)}
                            aria-describedby={describedBy('reissue-sans-notice', SAN_FIELDS)}
                            className={`${inputClass} resize-none font-mono${invalidClass(SAN_FIELDS)}`}
                        />
                        <FieldNotices id="reissue-sans-notice" notices={notices} field={SAN_FIELDS} />
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
                                max={form.notAfter || undefined}
                                onChange={(e) => updateField('notBefore', e.target.value)}
                                disabled={submitting}
                                aria-invalid={hasFieldNotice(notices, NOT_BEFORE_FIELDS)}
                                aria-describedby={describedBy('reissue-not-before-notice', NOT_BEFORE_FIELDS)}
                                className={inputClass + invalidClass(NOT_BEFORE_FIELDS)}
                            />
                            <FieldNotices id="reissue-not-before-notice" notices={notices} field={NOT_BEFORE_FIELDS} />
                            <div className={helperClass}>Leave blank to use the current time.</div>
                        </div>
                        <div>
                            <label htmlFor="reissue-not-after" className={labelClass}>Valid To (notAfter)</label>
                            <input
                                id="reissue-not-after"
                                type="datetime-local"
                                value={form.notAfter}
                                min={form.notBefore || undefined}
                                onChange={(e) => updateField('notAfter', e.target.value)}
                                disabled={submitting}
                                aria-invalid={hasFieldNotice(notices, NOT_AFTER_FIELDS) || validityInverted}
                                aria-describedby={describedBy('reissue-not-after-notice', NOT_AFTER_FIELDS)}
                                className={inputClass + invalidClass(NOT_AFTER_FIELDS)}
                            />
                            <FieldNotices id="reissue-not-after-notice" notices={notices} field={NOT_AFTER_FIELDS} />
                            <div className={helperClass}>Leave blank to use the signing profile's default (recommended).</div>
                            {validityInverted && (
                                <FieldHint tone="warn">Valid To must be later than Valid From; as entered, the certificate would expire before it became valid. Reissue is disabled until the order is fixed.</FieldHint>
                            )}
                        </div>
                    </div>

                    {/* Error — the parts of the refusal that belong to no control on this form.
                        role="alert" because it appears in response to the operator's own click and
                        is the reason the modal is still open; it does not move focus, so a caret
                        left in the Valid To box stays there. */}
                    {bannerNotices.length > 0 && (
                        <div role="alert" className="px-3 py-2 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700/50 rounded text-sm text-red-800 dark:text-red-300 space-y-2 max-h-60 overflow-y-auto">
                            {bannerNotices.map((n, i) => (
                                <div key={i} className="space-y-1">
                                    {n.title && n.title !== n.detail && <p className="font-semibold break-words">{n.title}</p>}
                                    {n.detail && <p className="break-words">{n.detail}</p>}
                                    {n.items && n.items.length > 0 && (
                                        <ul className="text-xs list-disc list-outside pl-4 space-y-0.5">
                                            {n.items.map((item, j) => <li key={j} className="break-words">{item}</li>)}
                                        </ul>
                                    )}
                                    {n.remediation && <p className="text-xs opacity-90 break-words">{n.remediation}</p>}
                                    {(n.code || n.correlationId) && (
                                        <p className="text-[11px] font-mono opacity-80 break-all select-all">
                                            {[n.code, n.correlationId].filter(Boolean).join(' · ')}
                                        </p>
                                    )}
                                </div>
                            ))}
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
                        disabled={submitting || validityInverted}
                        title={validityInverted ? 'Valid To must be later than Valid From' : undefined}
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
