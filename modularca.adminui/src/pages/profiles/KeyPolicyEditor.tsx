import React from 'react';
import { labelClass, inputClassNarrow } from '@shared/components/forms';
import { CheckboxRow, ProblemList, checkboxInputClass, radioInputClass, type FieldProblem } from '@shared/components/CheckboxList';
import { parseListField } from './profileFormCore';
import {
    KEY_FAMILIES, PRESETS, RSA_PSS_DEFAULT, RSA_SIGNATURE_GRID,
    type KeyFamily, type KeyPolicyLists, type KeyPolicyState,
    applyPreset, describePolicy, hashLabel, parentAllows, problems as findProblems, setAlgorithms, setFamily, setMode, setSignature, setSize,
    sizeLabel, variantLabel, type KeyPolicyDescription,
} from './keyPolicy';

export interface ParentKeyPolicy {
    name: string;
    lists: KeyPolicyLists;
}

/** A checkbox that can show the mixed state, for a family with some variants ticked. */
const TriCheckbox: React.FC<{ checked: boolean; mixed: boolean; disabled?: boolean; onChange: (on: boolean) => void; title?: string }> = ({ checked, mixed, disabled, onChange, title }) => {
    const ref = React.useRef<HTMLInputElement>(null);
    React.useEffect(() => { if (ref.current) ref.current.indeterminate = mixed; }, [mixed]);
    return (
        <input ref={ref} type="checkbox" className={checkboxInputClass} checked={checked} disabled={disabled} title={title}
            onChange={(e) => onChange(e.target.checked)} />
    );
};

const presetClass = inputClassNarrow.replace('py-2', 'py-1').replace('text-sm', 'text-xs');

const toFieldProblems = (list: { tone: FieldProblem['tone']; message: string }[]): FieldProblem[] =>
    list.map((p) => ({ tone: p.tone, message: p.message }));

/// <summary>
/// Edits a profile's key algorithms, key sizes and signature algorithms as one set of key families.
/// With <c>scope="algorithms"</c> it edits only the algorithm list, for a signing profile. A parent
/// profile's effective lists disable what the parent does not allow.
/// </summary>
export const KeyPolicyEditor: React.FC<{
    value: KeyPolicyState;
    onChange: (next: KeyPolicyState) => void;
    scope?: 'full' | 'algorithms';
    parent?: ParentKeyPolicy | null;
    legend?: string;
    id?: string;
}> = ({ value: s, onChange, scope = 'full', parent, legend, id = 'key-policy' }) => {
    const full = scope === 'full';
    const parentLists = parent?.lists ?? null;
    const notAllowed = parent ? `Not allowed by the parent profile “${parent.name}”.` : undefined;
    const allowed = (dim: keyof KeyPolicyLists, v: string) => parentAllows(parentLists, dim, v);

    const all = findProblems(s, { parent: parentLists, scope });
    const general = all.filter((p) => !p.family);
    const hintId = `${id}-hint`;
    const generalId = `${id}-problems`;

    const anyLabel = parent ? 'Same as the parent profile' : full ? 'Any key and signature' : 'Any algorithm';
    const hint = parent
        ? 'Same as the parent leaves the lists empty, so the parent’s lists apply. Only these narrows them; options the parent does not allow are disabled.'
        : full
            ? 'A ceiling on the keys and signatures a request may use. Any leaves the lists empty, which the server reads as unrestricted.'
            : 'The key algorithms this profile will sign for. Any leaves the list empty, which the server reads as unrestricted. Key sizes, curves and signature algorithms are limited on each cert profile.';

    const algorithmGrid = (
        <div className="mt-2 grid grid-cols-[auto_1fr] items-baseline gap-x-4 gap-y-1.5">
            {KEY_FAMILIES.map((fam) => (
                <React.Fragment key={fam.id}>
                    <span className="text-xs text-ink-muted">{fam.label}{fam.postQuantum ? ' (post-quantum)' : ''}</span>
                    <div className="flex flex-wrap gap-x-4 gap-y-1">
                        {fam.algorithms.map((a) => (
                            <CheckboxRow key={a} checked={s.algorithms.includes(a) && allowed('algorithms', a)}
                                option={{ value: a, label: a, disabled: !allowed('algorithms', a), disabledReason: notAllowed }}
                                onChange={(v) => onChange(setAlgorithms(s, [a], v, parentLists))} />
                        ))}
                    </div>
                </React.Fragment>
            ))}
        </div>
    );

    const familyBody = (fam: KeyFamily) => {
        const ticked = fam.algorithms.filter((a) => s.algorithms.includes(a) && allowed('algorithms', a));
        const famProblems = all.filter((p) => p.family === fam.id);
        const famProblemsId = `${id}-${fam.id}-problems`;
        const famEnabled = fam.algorithms.some((a) => allowed('algorithms', a));
        const multi = fam.algorithms.length > 1;
        const on = ticked.length > 0;
        const variantText = fam.variantLabels || multi ? fam.algorithms.map((a) => variantLabel(fam, a)).join(' / ') : '';

        return (
            <fieldset key={fam.id} className="min-w-0 rounded border border-line bg-raised px-3 py-2" aria-describedby={famProblems.length ? famProblemsId : undefined}>
                <legend className="px-1">
                    <label className={`flex items-center gap-2 ${famEnabled ? 'cursor-pointer' : 'cursor-not-allowed opacity-60'}`} title={famEnabled ? undefined : notAllowed}>
                        <TriCheckbox checked={on} mixed={on && ticked.length < fam.algorithms.filter((a) => allowed('algorithms', a)).length}
                            disabled={!famEnabled} onChange={(v) => onChange(setFamily(s, fam.id, v, parentLists))} />
                        <span className="text-sm font-medium text-ink">{fam.label}</span>
                        {variantText && !(on && multi) && <span className="text-xs text-ink-muted">{variantText}</span>}
                        {fam.postQuantum && <span className="text-xs text-ink-muted">(post-quantum)</span>}
                        {!famEnabled && <span className="sr-only">{notAllowed}</span>}
                    </label>
                </legend>
                {on && (
                    <div className="mt-1 space-y-2 pl-6">
                        {multi && (
                            <fieldset className="min-w-0">
                                <legend className="sr-only">{fam.label} variants</legend>
                                <div className="flex flex-wrap gap-x-4 gap-y-1">
                                    {fam.algorithms.map((a) => (
                                        <CheckboxRow key={a} checked={s.algorithms.includes(a) && allowed('algorithms', a)}
                                            option={{ value: a, label: variantLabel(fam, a), disabled: !allowed('algorithms', a), disabledReason: notAllowed }}
                                            onChange={(v) => onChange(setAlgorithms(s, [a], v, parentLists))} />
                                    ))}
                                </div>
                            </fieldset>
                        )}
                        {full && fam.sizes.length > 0 && (
                            <fieldset className="min-w-0">
                                <legend className="float-left w-20 pt-0.5 text-xs text-ink-muted">{fam.sizeNoun}</legend>
                                <div className="ml-20 flex flex-wrap gap-x-4 gap-y-1">
                                    {fam.sizes.map((v) => (
                                        <CheckboxRow key={v} checked={s.sizes.includes(v) && allowed('sizes', v)}
                                            option={{ value: v, label: sizeLabel(v), disabled: !allowed('sizes', v), disabledReason: notAllowed }}
                                            onChange={(c) => onChange(setSize(s, v, c, parentLists))} />
                                    ))}
                                </div>
                            </fieldset>
                        )}
                        {full && !fam.fixedSignature && (
                            <fieldset className="min-w-0">
                                <legend className="float-left w-20 pt-0.5 text-xs text-ink-muted">Signatures</legend>
                                {fam.id === 'RSA' ? (
                                    <table className="ml-20 text-sm">
                                        <thead>
                                            <tr className="text-xs text-ink-muted">
                                                <th scope="col" className="pr-2"><span className="sr-only">Hash</span></th>
                                                <th scope="col" className="px-2 text-left font-normal">PSS (server default)</th>
                                                <th scope="col" className="px-2 text-left font-normal">PKCS#1 v1.5</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {RSA_SIGNATURE_GRID.map((r) => (
                                                <tr key={r.hash}>
                                                    <th scope="row" className="pr-2 text-left font-normal text-ink">{r.hash}</th>
                                                    {[r.pss, r.pkcs1].map((sig) => (
                                                        <td key={sig} className="px-2 py-0.5">
                                                            <label className={`flex items-center gap-1.5 ${allowed('signatures', sig) ? 'cursor-pointer' : 'cursor-not-allowed opacity-60'}`} title={allowed('signatures', sig) ? sig : notAllowed}>
                                                                <input type="checkbox" className={checkboxInputClass} checked={s.signatures.includes(sig) && allowed('signatures', sig)}
                                                                    disabled={!allowed('signatures', sig)} onChange={(e) => onChange(setSignature(s, sig, e.target.checked, parentLists))} />
                                                                <span className="sr-only">{r.hash} {sig === r.pss ? 'PSS' : 'PKCS#1 v1.5'}{sig === RSA_PSS_DEFAULT ? ', the server default' : ''}</span>
                                                            </label>
                                                        </td>
                                                    ))}
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                ) : (
                                    <div className="ml-20 flex flex-wrap gap-x-4 gap-y-1">
                                        {fam.signatures.map((sig) => (
                                            <CheckboxRow key={sig} checked={s.signatures.includes(sig) && allowed('signatures', sig)}
                                                option={{ value: sig, label: hashLabel(sig), disabled: !allowed('signatures', sig), disabledReason: notAllowed }}
                                                onChange={(c) => onChange(setSignature(s, sig, c, parentLists))} />
                                        ))}
                                    </div>
                                )}
                            </fieldset>
                        )}
                    </div>
                )}
                <ProblemList id={famProblemsId} problems={toFieldProblems(famProblems)} />
            </fieldset>
        );
    };

    return (
        <fieldset id={id} className="min-w-0" aria-describedby={[hintId, general.length ? generalId : null].filter(Boolean).join(' ')}>
            <legend className={labelClass}>{legend ?? (full ? 'Keys and signatures' : 'Allowed algorithms')}</legend>
            <div role="radiogroup" aria-label={`${legend ?? (full ? 'Keys and signatures' : 'Allowed algorithms')} restriction`} className="flex flex-wrap gap-x-5 gap-y-1 text-sm text-ink">
                <label className="flex items-center gap-2 cursor-pointer">
                    <input type="radio" name={`${id}-mode`} className={radioInputClass} checked={s.mode === 'any'} onChange={() => onChange(setMode(s, 'any'))} />
                    {anyLabel}
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                    <input type="radio" name={`${id}-mode`} className={radioInputClass} checked={s.mode === 'only'} onChange={() => onChange(setMode(s, 'only'))} />
                    Only these
                </label>
            </div>
            <p id={hintId} className="mt-1 text-xs text-ink-muted">{hint}</p>
            {s.mode === 'only' && !full && algorithmGrid}
            {s.mode === 'only' && full && (
                <div className="mt-2 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                        <label htmlFor={`${id}-preset`} className="text-xs text-ink-muted">Fill from a preset</label>
                        <select id={`${id}-preset`} value="" className={presetClass}
                            aria-describedby={`${id}-preset-hint`}
                            onChange={(e) => {
                                const p = PRESETS.find((x) => x.id === e.target.value);
                                if (p) onChange(applyPreset(s, p, parentLists));
                            }}>
                            <option value="">Choose…</option>
                            {PRESETS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                        </select>
                        <span id={`${id}-preset-hint`} className="text-xs text-ink-muted">Replaces the ticks below; they stay editable.</span>
                    </div>
                    {KEY_FAMILIES.map(familyBody)}
                </div>
            )}
            <ProblemList id={generalId} problems={toFieldProblems(full ? general : all)} />
        </fieldset>
    );
};

const valueText = (values: string[] | 'any', anyText: string) =>
    values === 'any' ? <span className="text-ink-muted">{anyText}</span> : values.length ? values.join(', ') : <span className="text-warn">None</span>;

/** Family headings, each followed by one labelled row per value list. */
const PolicyDescription: React.FC<{ d: KeyPolicyDescription; anyText: string }> = ({ d, anyText }) => {
    if (d.any) return <span className="text-xs text-warn">{anyText}</span>;
    return (
        <div className="mt-1 space-y-2 text-sm">
            {d.families.map((f) => (
                <div key={f.family}>
                    <div className="font-medium text-ink">
                        {f.family}{f.postQuantum && <span className="ml-1.5 text-xs font-normal text-ink-muted">post-quantum</span>}
                    </div>
                    <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-0.5 pl-3 text-ink">
                        {f.variants.length > 0 && (f.sizes || f.signatures) && (<><dt className="text-xs text-ink-muted">Variants</dt><dd>{f.variants.join(', ')}</dd></>)}
                        {f.variants.length > 0 && !f.sizes && !f.signatures && (<dd className="col-span-2">{f.variants.join(', ')}</dd>)}
                        {f.sizes && (<><dt className="text-xs text-ink-muted">{f.sizes.noun}</dt><dd>{valueText(f.sizes.values, f.sizes.noun === 'Curves' ? 'Any curve' : 'Any size')}</dd></>)}
                        {f.signatures && (<><dt className="text-xs text-ink-muted">Signatures</dt><dd>{valueText(f.signatures, 'Any signature')}</dd></>)}
                    </dl>
                </div>
            ))}
            {d.extras.length > 0 && (
                <div className="text-xs text-ink-muted">Also stored, not recognised: <span className="data-mono">{d.extras.join(', ')}</span></div>
            )}
        </div>
    );
};

/** Read-only "Keys and signatures": a heading per allowed family with its sizes and signatures. */
export const KeyPolicySummary: React.FC<{ algorithms: any; sizes: any; signatures: any }> = ({ algorithms, sizes, signatures }) => {
    if ([algorithms, sizes, signatures].some((v) => v === undefined || v === null)) {
        return <span className="text-xs text-ink-muted">—</span>;
    }
    const d = describePolicy({ algorithms: parseListField(algorithms), sizes: parseListField(sizes), signatures: parseListField(signatures) });
    return <PolicyDescription d={d} anyText="Unrestricted — every key and signature is permitted" />;
};

/** Read-only signing profile Allowed Algorithms, grouped by family. */
export const AlgorithmSummary: React.FC<{ items: any }> = ({ items }) => {
    if (items === undefined || items === null) return <span className="text-xs text-ink-muted">—</span>;
    const d = describePolicy({ algorithms: parseListField(items) }, 'algorithms');
    return <PolicyDescription d={d} anyText="Unrestricted — every algorithm is permitted" />;
};

export default KeyPolicyEditor;
