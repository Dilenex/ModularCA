import React, { useEffect, useRef, useState } from 'react';
import { FieldHint, labelClass } from '@shared/components/forms';
import { KeyValueTable, RowTableEditor } from '@shared/components/RowTableEditor';
import { type KeyValueRow, findRowProblems, hasRowErrors } from '@shared/components/rowTable';
import { listFromValue } from '@shared/components/chipList';
import { apiGet } from '../api/client';
import {
    type MappingGroup, mappingRowsFromStored, mappingRowsToJson, mappingTargetOptions, mappingTargetProblems, normalizeDnKey,
    storedMappingPairs, validateLdapDn,
} from './ldapMappings';
import { type SunsetRow, SUNSET_COLUMNS, sunsetRowsFromList, sunsetRowsToList } from './sunsetRules';

/**
 * Keeps editor rows for a setting the page stores serialised. Rows are the state, so an incomplete
 * row survives typing; the serialised value is reported on every change, and the rows are re-read
 * when the setting changes from outside (load, save).
 */
function useSeededRows<R, V>(value: V, read: (v: V) => R[], write: (rows: R[]) => V, key: (v: V) => string, onChange: (v: V) => void) {
    const [rows, setRows] = useState<R[]>(() => read(value));
    const emitted = useRef(key(value));
    useEffect(() => {
        if (key(value) !== emitted.current) {
            emitted.current = key(value);
            setRows(read(value));
        }
    }, [key(value)]); // eslint-disable-line react-hooks/exhaustive-deps
    const change = (next: R[]) => {
        setRows(next);
        const out = write(next);
        emitted.current = key(out);
        onChange(out);
    };
    return { rows, change };
}

const useReportInvalid = (invalid: boolean, onInvalidChange?: (invalid: boolean) => void) => {
    useEffect(() => { onInvalidChange?.(invalid); }, [invalid]); // eslint-disable-line react-hooks/exhaustive-deps
};

/**
 * Settings › Certificate Policy › Algorithm Sunset Rules: rows of an algorithm and a date, stored
 * as `ALG:YYYY-MM-DD`. Invalid rows are marked and reported through `onInvalidChange`.
 */
export const SunsetRulesEditor: React.FC<{ value: unknown; onChange: (rules: string[]) => void; onInvalidChange?: (invalid: boolean) => void }> = ({ value, onChange, onInvalidChange }) => {
    const { rows, change } = useSeededRows<SunsetRow, string[]>(
        listFromValue(value), sunsetRowsFromList, sunsetRowsToList, (v) => JSON.stringify(v), onChange);
    useReportInvalid(hasRowErrors(rows, SUNSET_COLUMNS), onInvalidChange);
    return (
        <fieldset className="min-w-0">
            <legend className={labelClass}>Algorithm Sunset Rules</legend>
            <RowTableEditor<SunsetRow> id="cert-policy-sunset" caption="Algorithm sunset rules" value={rows} onChange={change}
                columns={SUNSET_COLUMNS} newRow={() => ({ algorithm: '', date: '' })} addLabel="+ Add rule"
                rowLabel={(r, i) => r.algorithm.trim() || `rule ${i + 1}`} emptyText="No sunset rules." aria-describedby="cert-policy-sunset-hint" />
            <FieldHint id="cert-policy-sunset-hint">
                From the date on, issuance with that algorithm is refused; in the 90 days before, it is allowed with a warning, so sunsets can be
                entered years ahead. The algorithm is compared, ignoring case, with the key algorithm and size (RSA-2048, ECDSA-P-256), the key
                algorithm alone (RSA, Ed25519, ML-DSA-65) or the signature algorithm (SHA1withRSA).
            </FieldHint>
        </fieldset>
    );
};

/**
 * Settings › LDAP Authentication › Group to Role Mappings: LDAP group DN → local group, stored as
 * a JSON object string. The value is rewritten only once a row is edited, so an untouched card
 * saves the stored string byte for byte (the server treats any change to it as super-only).
 * `savedValue` is the setting as last saved, which decides what counts as "stored unchanged".
 */
export const LdapMappingsEditor: React.FC<{ value: unknown; savedValue: unknown; onChange: (json: string) => void; disabled?: boolean; onInvalidChange?: (invalid: boolean) => void }> = ({ value, savedValue, onChange, disabled, onInvalidChange }) => {
    const stored = typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value);
    const { rows, change } = useSeededRows<KeyValueRow, string>(
        stored, (v) => mappingRowsFromStored(v).rows, mappingRowsToJson, (v) => v, onChange);
    const saved = mappingRowsFromStored(savedValue);
    const storedPairs = storedMappingPairs(saved.rows);
    const notices = saved.notices;

    const [groups, setGroups] = useState<MappingGroup[] | null>(null);
    useEffect(() => {
        if (disabled) return;
        let active = true;
        apiGet<any>('/api/v1/admin/groups')
            .then((data) => { if (active) setGroups(Array.isArray(data) ? data : (data?.items ?? [])); })
            .catch(() => { if (active) setGroups(null); });
        return () => { active = false; };
    }, [disabled]);

    const keyColumn = { label: 'LDAP group DN', required: true, mono: true, placeholder: 'CN=PKI Operators,OU=Groups,DC=example,DC=com', validate: (v: string) => validateLdapDn(v) };
    const valueColumn = { label: 'Local group', required: true, width: '16rem', placeholder: groups ? 'Choose a group…' : 'Group name', options: groups ? mappingTargetOptions(groups) : undefined };
    const rowProblems = (row: KeyValueRow) => mappingTargetProblems(row, groups, storedPairs);
    const invalid = findRowProblems(rows, [{ ...keyColumn, key: 'key', kind: 'text' }, { ...valueColumn, key: 'value', kind: 'text' }],
        { duplicateKey: { column: 'key', normalize: normalizeDnKey } }).some((p) => p.tone === 'error')
        || rows.some((r) => rowProblems(r).some((p) => p.tone === 'error'));
    useReportInvalid(invalid, onInvalidChange);

    return (
        <fieldset className="min-w-0">
            <legend className={labelClass}>Group to Role Mappings</legend>
            {notices.length > 0 && <ul className="mb-2 text-xs text-warn list-disc list-inside">{notices.map((n, i) => <li key={i}>{n}</li>)}</ul>}
            <KeyValueTable id="ldap-group-mappings" caption="LDAP group to local group mappings" value={rows} onChange={change}
                keyColumn={keyColumn} valueColumn={valueColumn} normalizeKey={normalizeDnKey}
                duplicateMessage={(dn, first) => `${dn} is already mapped in row ${first + 1}; one LDAP group maps to one local group.`}
                rowProblems={rowProblems} addLabel="+ Add mapping" disabled={disabled}
                emptyText="No mappings: LDAP sign-in grants no group membership." aria-describedby="ldap-group-mappings-hint" />
            <FieldHint id="ldap-group-mappings-hint">
                Each LDAP group grants membership of one local group; an LDAP group can be listed once, so to grant two local groups,
                map two LDAP groups. Write the DN as the directory reports it in the user&apos;s group attribute (case does not matter).
                System and privilege-controlled groups are not offered: their membership changes only through the ceremony-gated admin
                paths. Only groups in a space are offered, since sync never grants an instance group. LDAP groups not listed grant nothing.
            </FieldHint>
        </fieldset>
    );
};
