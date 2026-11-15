import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { StepUpOps } from '@shared/generated';
import { InlineNotice } from '@shared/components/InlineNotice';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { actionButtonDanger } from '@shared/components/actionButtons';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { REVOCATION_REASONS } from '../pages/CertificateDetail';
import ConfirmModal from './ConfirmModal';
import {
    bulkBody, missingRows, missingSummary, recordable, revokeAllBody, revokeAllConfirmation, selectionIsWholeList,
    MISSING_FROM_CRL_ANCHOR, type MissingFromCrl, type MissingSerialRow,
} from './missingFromCrl';

function formatDate(d: string | null | undefined) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const field = 'w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent disabled:opacity-50';
const cancelButton = 'px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50';
const confirmDanger = 'px-4 py-2 text-sm bg-crit text-on-accent rounded hover:bg-crit-hover transition-colors disabled:opacity-50';

/// <summary>
/// On a CA's page, only while the signer refuses the CA's CRL for leaving out revoked serials:
/// every serial the refused CRL left out, with the reason and date the last signed CRL gives, and
/// the "revoke a serial number alone" action for one or for those selected. A serial the CA still
/// holds a certificate for links to that certificate, where it is revoked. Recording asks for the
/// same step-up as revoking one serial does. Revoking all of them is an act of its own, set apart
/// below the list: it asks for the CA's name to be typed and for its own step-up, and the server
/// refuses it when the list is no longer the one that was confirmed. Shown to a caller with
/// cert.revoke on the CA.
/// </summary>
const MissingFromCrlPanel: React.FC<{ caId: string; caName: string; onChanged?: () => void }> = ({ caId, caName, onChanged }) => {
    const { requireStepUp } = useStepUp();
    const [answer, setAnswer] = useState<MissingFromCrl | null>(null);
    const [loadError, setLoadError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [pending, setPending] = useState<MissingSerialRow[] | null>(null);
    const [note, setNote] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [done, setDone] = useState<string | null>(null);
    // Revoke all: its own dialog, with the CA's name typed in.
    const [allOpen, setAllOpen] = useState(false);
    const [typedName, setTypedName] = useState('');

    useEffect(() => {
        let cancelled = false;
        apiGet<MissingFromCrl>(`/api/v1/admin/authorities/${caId}/revoked-serials/missing-from-crl`, { toast: false })
            .then((data) => { if (!cancelled) { setAnswer(data); setLoadError(null); } })
            .catch((err) => { if (!cancelled) setLoadError(errorNotice(err, 'Failed to load the serials missing from the CRL')); });
        return () => { cancelled = true; };
    }, [caId, refresh]);

    const rows = missingRows(answer);

    // A link from elsewhere names this section: bring it into view once its rows are there.
    useEffect(() => {
        if (rows.length > 0 && window.location.hash === `#${MISSING_FROM_CRL_ANCHOR}`)
            document.getElementById(MISSING_FROM_CRL_ANCHOR)?.scrollIntoView({ block: 'start' });
    }, [rows.length]);

    // Escape closes the dialog, as Cancel does, unless a request is under way.
    useEffect(() => {
        if (!pending) return;
        const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !busy) setPending(null); };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [pending, busy]);

    const defaultNote = 'Revoked again after the database was taken back: the signer\'s last CRL lists it.';

    const askAll = () => {
        setNote(defaultNote); setTypedName('');
        setError(null); setDone(null); setAllOpen(true);
    };

    const submitAll = async () => {
        if (!answer || !revokeAllConfirmation(answer, caName, typedName, note)?.canConfirm) return;
        setBusy(true); setError(null);
        try {
            const res = await apiPostWithMfa<any>(`/api/v1/admin/authorities/${caId}/revoked-serials/missing-from-crl/revoke-all`,
                revokeAllBody(answer, note), requireStepUp, StepUpOps.RevokeAllMissingSerials, caId);
            const recorded = typeof res?.recorded === 'number' ? res.recorded : 0;
            const refused = typeof res?.refusedCount === 'number' ? res.refusedCount : 0;
            setDone(`All ${recorded} serial${recorded === 1 ? '' : 's'} recorded as revoked${res?.crlNumber ? ` and listed on CRL ${res.crlNumber}` : '; the next CRL lists them'}.`
                + (refused > 0 ? ` ${refused} could not be recorded: ${res.refused?.[0]?.reason ?? ''}` : ''));
            setAllOpen(false);
            setRefresh((r) => r + 1);
            onChanged?.();
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled') {
                setError(errorNotice(err, 'The serials were not revoked'));
                // The list may be what changed: read it again, so the dialog shows what is there now.
                setRefresh((r) => r + 1);
            }
        } finally {
            setBusy(false);
        }
    };

    const ask = (selected: MissingSerialRow[]) => {
        // Every serial on the list is not a selection: that is revoke-all, and the server says the same.
        if (selectionIsWholeList(selected, rows)) { askAll(); return; }
        setNote(defaultNote);
        setError(null); setDone(null); setPending(recordable(selected));
    };

    const submit = async () => {
        if (!pending) return;
        setBusy(true); setError(null);
        try {
            const res = await apiPostWithMfa<any>(`/api/v1/admin/authorities/${caId}/revoked-serials/bulk`, bulkBody(pending, note), requireStepUp, StepUpOps.RevokeSerial, caId);
            const recorded = Array.isArray(res?.recorded) ? res.recorded.length : 0;
            const refused = Array.isArray(res?.refused) ? res.refused.length : 0;
            setDone(`${recorded} serial${recorded === 1 ? '' : 's'} recorded as revoked${res?.crlNumber ? ` and listed on CRL ${res.crlNumber}` : '; the next CRL lists them'}.`
                + (refused > 0 ? ` ${refused} could not be recorded: ${res.refused[0].reason}` : ''));
            setPending(null);
            setRefresh((r) => r + 1);
            onChanged?.();
        } catch (err: any) {
            // Cancelling the step-up prompt is a deliberate choice, not a failure to report.
            if (err?.message !== 'Step-up MFA cancelled') setError(errorNotice(err, 'The serials were not recorded'));
        } finally {
            setBusy(false);
        }
    };

    const columns: DataTableColumn<MissingSerialRow>[] = [
        { key: 'serial', header: 'Serial', defaultWidth: 280, minWidth: 140, sortable: true, exportValue: (r) => r.serialNumber, render: (r) => <span className="data-mono text-ink break-all">{r.serialNumber}</span> },
        { key: 'reason', header: 'Reason', defaultWidth: 170, sortable: true, exportValue: (r) => r.reason, render: (r) => <span className="text-ink">{REVOCATION_REASONS.find((x) => x.value === r.reason)?.label ?? r.reason}</span> },
        { key: 'revoked', header: 'Revoked', defaultWidth: 170, sortable: true, sortValue: (r) => r.revocationDate, exportValue: (r) => r.revocationDate, render: (r) => <span className="text-ink-muted whitespace-nowrap">{formatDate(r.revocationDate)}</span> },
        { key: 'held', header: 'This CA holds', defaultWidth: 190, truncate: false, sortable: true, sortValue: (r) => (r.certificateHeld ? 1 : 0), exportValue: (r) => (r.certificateHeld ? 'certificate' : 'nothing'), render: (r) => (
            r.certificateHeld
                ? <Link to={`/certificates/${r.serialNumber}`} className="text-accent-ink underline whitespace-nowrap" onClick={(e) => e.stopPropagation()}>The certificate: revoke it there</Link>
                : <span className="text-ink-muted whitespace-nowrap">No certificate</span>
        ) },
        { key: 'action', header: '', defaultWidth: 150, truncate: false, render: (r) => (
            r.certificateHeld ? null : <button type="button" onClick={(e) => { e.stopPropagation(); ask([r]); }} className={actionButtonDanger}>Revoke serial</button>
        ) },
    ];

    if (loadError) return <InlineNotice notice={loadError} />;
    if (rows.length === 0)
        return done ? <div className="rounded border border-ok/40 bg-ok-soft p-3 max-w-3xl"><p className="text-xs text-ok">{done}</p></div> : null;

    const open = recordable(rows);
    return (
        <div id={MISSING_FROM_CRL_ANCHOR} className="space-y-3 scroll-mt-4">
            <div className="rounded border border-crit/40 bg-crit-soft p-3 max-w-3xl flex items-start gap-2">
                <StatusBadge status="revoked" label="CRL refused" />
                <p className="text-xs text-ink">
                    {missingSummary(rows)} The CRL already published stays in force until it runs out; no new one is signed for this CA until
                    every serial below is revoked again.
                </p>
            </div>
            {done && (
                <div className="rounded border border-ok/40 bg-ok-soft p-3 max-w-3xl">
                    <p className="text-xs text-ok">{done}</p>
                </div>
            )}
            <div className="overflow-x-auto">
                <DataTable<MissingSerialRow>
                    tableId="ca-missing-from-crl"
                    title="Serials missing from the CRL"
                    rows={rows}
                    rowKey={(r) => r.serialNumber}
                    columns={columns}
                    findable
                    selectable
                    rowSelectable={(r) => !r.certificateHeld}
                    bulkActions={[{ label: 'Revoke the selected serials', variant: 'danger', onClick: (selected) => ask(selected) }]}
                    empty="No serial is missing from the CRL"
                />
            </div>

            {/* Set apart from the list and its row actions: revoking everything is not a slip away from revoking a selection. */}
            {open.length > 1 && (
                <div className="mt-6 pt-4 border-t border-line max-w-3xl flex flex-wrap items-center gap-3">
                    <div className="flex-1 min-w-[16rem]">
                        <div className="text-sm font-medium text-ink">Revoke all {open.length} serials</div>
                        <p className="text-xs text-ink-muted">
                            Revokes every serial on this list that has no certificate here, in one act. It asks for the name of the
                            certificate authority and cannot be undone.
                        </p>
                    </div>
                    <button type="button" onClick={askAll} className={actionButtonDanger}>Revoke all…</button>
                </div>
            )}

            {(() => {
                const confirmation = allOpen ? revokeAllConfirmation(answer, caName, typedName, note) : null;
                if (!confirmation) return null;
                return (
                    <ConfirmModal
                        isOpen
                        title={confirmation.title}
                        tone="crit"
                        confirmLabel={confirmation.confirmLabel}
                        loading={busy}
                        confirmDisabled={!confirmation.canConfirm}
                        onConfirm={submitAll}
                        onCancel={() => { if (!busy) setAllOpen(false); }}
                        message={(
                            <div className="space-y-3">
                                <div className="space-y-1"><div className="text-xs text-ink-muted">Certificate authority</div><div className="text-sm text-ink break-all">{confirmation.caName}</div></div>
                                <div className="space-y-1"><div className="text-xs text-ink-muted">Serials to revoke</div><div className="text-sm text-ink">{confirmation.count}</div></div>
                                {confirmation.statements.map((s) => <p key={s} className="text-xs text-ink">{s}</p>)}
                                <div className="space-y-1">
                                    <label htmlFor="revoke-all-note" className="block text-xs text-ink-muted">Why are they revoked without their certificates?</label>
                                    <textarea id="revoke-all-note" value={note} onChange={(e) => setNote(e.target.value)} disabled={busy} rows={2} maxLength={1000} className={field} />
                                </div>
                                <div className="space-y-1">
                                    <label htmlFor="revoke-all-name" className="block text-xs text-ink-muted">{confirmation.prompt}</label>
                                    <input id="revoke-all-name" type="text" value={typedName} onChange={(e) => setTypedName(e.target.value)} disabled={busy}
                                        autoComplete="off" spellCheck={false} className={field} />
                                </div>
                                {error && <InlineNotice notice={error} />}
                            </div>
                        )}
                    />
                );
            })()}

            {pending && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim" onClick={() => !busy && setPending(null)}>
                    <div className="bg-raised border border-line rounded-lg shadow-xl w-full max-w-lg mx-4" role="dialog" aria-modal="true"
                        aria-label="Revoke serials missing from the CRL" onClick={(e) => e.stopPropagation()}>
                        <div className="px-6 py-4 border-b border-line">
                            <h2 className="text-lg font-semibold text-ink">
                                Revoke {pending.length} serial{pending.length === 1 ? '' : 's'} without {pending.length === 1 ? 'its certificate' : 'their certificates'}
                            </h2>
                        </div>
                        <div className="px-6 py-4 space-y-4">
                            <div className="space-y-1"><div className="text-xs text-ink-muted">Certificate authority</div><div className="text-sm text-ink break-all">{caName}</div></div>
                            <p className="text-xs text-ink-muted">
                                Each serial is recorded as revoked with the reason the signer's last CRL gives. The revocation is permanent, and its
                                date is now. The CRL is generated once, after the last.
                            </p>
                            <div className="space-y-1">
                                <label htmlFor="missing-note" className="block text-xs text-ink-muted">Why are they revoked without their certificates?</label>
                                <textarea id="missing-note" value={note} onChange={(e) => setNote(e.target.value)} disabled={busy} rows={2} maxLength={1000} className={field} />
                            </div>
                            {error && <InlineNotice notice={error} />}
                        </div>
                        <div className="px-6 py-4 border-t border-line flex justify-end gap-3">
                            <button type="button" onClick={() => setPending(null)} disabled={busy} className={cancelButton}>Cancel</button>
                            <button type="button" onClick={submit} disabled={busy || pending.length === 0 || note.trim().length === 0} className={confirmDanger}>
                                {busy ? 'Working…' : `Revoke ${pending.length} serial${pending.length === 1 ? '' : 's'}`}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default MissingFromCrlPanel;
