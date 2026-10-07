import React from 'react';
import { FieldHint, labelClass } from '@shared/components/forms';
import { RowTableEditor } from '@shared/components/RowTableEditor';
import { checkboxClass } from './CertProfileForm';
import {
    type PolicyRow, POLICY_CHECKS, POLICY_COLUMNS, blankPolicyRow, policiesFromStored, policyLabel, policyRowProblems,
} from './certificatePolicies';

/**
 * The signing profile's Certificate Policies: one row per policy (OID, CPS URI, user notice), one
 * checkbox for the extension's criticality, and the notices for anything loading dropped.
 */
export const CertificatePoliciesEditor: React.FC<{
    rows: PolicyRow[];
    critical: boolean;
    notices: string[];
    onChange: (next: { rows: PolicyRow[]; critical: boolean }) => void;
    id: string;
}> = ({ rows, critical, notices, onChange, id }) => {
    const hasRows = rows.some((r) => r.oid.trim() || r.cpsUri.trim() || r.userNotice.trim());
    return (
        <fieldset className="min-w-0">
            <legend className={labelClass}>Certificate Policies</legend>
            {notices.length > 0 && (
                <div className="mb-2 rounded border border-warn/40 bg-warn-soft px-3 py-2 text-xs text-warn" role="status">
                    <p className="font-semibold">Stored qualifiers the server never used will be removed when this profile is saved:</p>
                    <ul className="mt-1 list-disc list-inside space-y-0.5">{notices.map((n, i) => <li key={i}>{n}</li>)}</ul>
                </div>
            )}
            <RowTableEditor<PolicyRow>
                id={id} caption="Certificate policies" value={rows} onChange={(next) => onChange({ rows: next, critical })}
                columns={POLICY_COLUMNS} checks={POLICY_CHECKS} newRow={blankPolicyRow}
                rowLabel={(r, i) => r.oid.trim() || `policy ${i + 1}`} addLabel="+ Add policy"
                emptyText="No policies: certificates carry no CertificatePolicies extension."
                aria-describedby={`${id}-hint`}
            />
            <label className="mt-2 flex items-center gap-2 text-xs text-ink">
                <input type="checkbox" checked={critical && hasRows} disabled={!hasRows}
                    onChange={(e) => onChange({ rows, critical: e.target.checked })} className={checkboxClass} />
                Mark the CertificatePolicies extension critical
            </label>
            <FieldHint id={`${id}-hint`}>
                Every certificate issued through this profile lists these policies. Type an OID or pick a suggestion
                (anyPolicy, or a CA/Browser Forum DV, OV, IV or EV policy). The CPS URI (http or https) and the user notice
                (at most 200 characters) are optional qualifiers. Critical applies to the whole extension; RFC 5280 recommends
                leaving it off unless relying parties must understand the policies.
            </FieldHint>
        </fieldset>
    );
};

/** The stored policies, read-only: a table of OID (with its name when known), CPS URI and notice. */
export const CertificatePoliciesView: React.FC<{ policyOids: unknown; policyQualifiersJson: unknown }> = ({ policyOids, policyQualifiersJson }) => {
    const { rows, critical, notices } = policiesFromStored(policyOids, policyQualifiersJson);
    if (rows.length === 0) return <p className="text-xs text-ink-muted">None: certificates carry no CertificatePolicies extension.</p>;
    const problems = policyRowProblems(rows);
    return (
        <div className="space-y-1">
            <table className="w-full text-xs border-collapse" aria-label="Certificate policies">
                <thead>
                    <tr className="text-left text-ink-muted">
                        <th scope="col" className="font-medium pr-3 pb-1">Policy OID</th>
                        <th scope="col" className="font-medium pr-3 pb-1">CPS URI</th>
                        <th scope="col" className="font-medium pb-1">User notice</th>
                    </tr>
                </thead>
                <tbody>
                    {rows.map((r, i) => {
                        const rowProblems = problems.filter((p) => p.index === i && p.tone === 'error');
                        return (
                            <tr key={i} className="align-top border-t border-line">
                                <td className="pr-3 py-1">
                                    <span className={`font-mono break-all ${rowProblems.some((p) => p.column === 'oid') ? 'text-crit' : 'text-ink'}`}>{r.oid}</span>
                                    {policyLabel(r.oid) && <span className="block text-ink-muted">{policyLabel(r.oid)}</span>}
                                    {rowProblems.map((p, j) => <span key={j} className="block text-crit">{p.message}</span>)}
                                </td>
                                <td className="pr-3 py-1 font-mono break-all text-ink">{r.cpsUri || <span className="text-ink-muted font-sans">—</span>}</td>
                                <td className="py-1 text-ink break-words">{r.userNotice || <span className="text-ink-muted">—</span>}</td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
            <p className="text-xs text-ink-muted">Extension critical: {critical ? 'Yes' : 'No'}</p>
            {notices.length > 0 && (
                <ul className="text-xs text-warn list-disc list-inside space-y-0.5">{notices.map((n, i) => <li key={i}>{n}</li>)}</ul>
            )}
        </div>
    );
};
