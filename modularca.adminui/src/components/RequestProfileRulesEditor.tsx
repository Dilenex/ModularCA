import React, { useEffect, useMemo, useRef, useState } from 'react';
import { labelClass } from '@shared/components/forms';
import { copyText } from '@shared/clipboard';

/**
 * The subject-DN and SAN rule editor for a request profile, shared by the create form on
 * /profiles (Request Profiles tab) and the edit view on /profiles/request/:id.
 *
 * It exists because those two were not the same editor. Creating a profile gave you a table of DN
 * rules and a row of SAN type toggles; editing the profile you had just created gave you two
 * textareas of raw JSON, so the only way to change a rule was to hand-write the shape the server
 * expects and hope. Same data, same endpoint, two different experiences, and the worse one was on
 * the page you visit far more often.
 *
 * Extracting the good one had a catch worth stating: the create form was not merely nicer, it was
 * also *lossy*. It always posted `sanRules.rules: {}`, so the per-SAN-type `regex` and `maxCount`
 * that the server has always accepted could not be expressed there at all — which is exactly why
 * the edit page's JSON textarea could not simply be deleted. This editor closes that gap instead:
 * per-type rules are editable here, so the structured form is now a complete expression of the
 * model rather than a convenient subset of it.
 *
 * JSON stays available as Import/Export rather than a live textarea: a request profile is a policy
 * object an operator may copy between environments or diff against a colleague's. "Paste JSON…"
 * checks the shape and previews it before anything replaces the rules, so the form itself never
 * holds unparseable text.
 */

import {
    DN_FIELD_OPTIONS, REQUIREMENT_OPTIONS, SAN_TYPE_OPTIONS, DEFAULT_SAN_MAX_COUNT,
    checkRulesImport, emptyDnRule, emptySanRules, emptyRules, parseRules, rulesToJsonText, serializeRules,
    type RequestProfileRules, type SanRulesModel, type SanTypeRule, type SubjectDnFieldRule,
} from './requestProfileRules';

export {
    emptyDnRule, emptySanRules, emptyRules, parseRules, serializeRules,
    type RequestProfileRules, type SanRulesModel, type SanTypeRule, type SubjectDnFieldRule,
};

const cellInput = 'bg-raised border border-line rounded px-1 py-1 text-ink text-xs';

interface Props {
    value: RequestProfileRules;
    onChange: (next: RequestProfileRules) => void;
}

const actionButton = 'px-2 py-1 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors';

/** "Copy as JSON" and "Paste JSON…": the rules as text, in and out. */
const RulesJsonActions: React.FC<Props> = ({ value, onChange }) => {
    const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle');
    const [pasteOpen, setPasteOpen] = useState(false);
    const text = useMemo(() => rulesToJsonText(value), [value]);

    useEffect(() => {
        if (copyState !== 'copied') return;
        const t = setTimeout(() => setCopyState('idle'), 2000);
        return () => clearTimeout(t);
    }, [copyState]);

    const copy = async () => setCopyState((await copyText(text)) ? 'copied' : 'failed');

    return (
        <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-ink-muted">Rules as JSON:</span>
                <button type="button" onClick={copy} className={actionButton}>Copy as JSON</button>
                <button type="button" onClick={() => setPasteOpen(true)} className={actionButton}>Paste JSON…</button>
                <span role="status" className="text-xs text-ok">{copyState === 'copied' ? 'Copied' : ''}</span>
            </div>
            {copyState === 'failed' && (
                <div className="space-y-1">
                    <p className="text-xs text-ink-muted">The clipboard is not available here; select the text and copy it.</p>
                    <textarea readOnly rows={10} value={text} spellCheck={false} aria-label="Request profile rules as JSON"
                        onFocus={(e) => e.currentTarget.select()}
                        className="w-full data-mono px-3 py-2 rounded bg-raised border border-line-strong text-ink focus:outline-none focus:border-accent" />
                    <button type="button" onClick={() => setCopyState('idle')} className="text-xs text-ink-muted hover:text-ink">Hide</button>
                </div>
            )}
            {pasteOpen && (
                <PasteRulesDialog current={value} onApply={(rules) => { onChange(rules); setPasteOpen(false); }} onCancel={() => setPasteOpen(false)} />
            )}
        </div>
    );
};

/** Paste, check and preview rules JSON; Apply replaces the rules, Cancel leaves them. */
const PasteRulesDialog: React.FC<{
    current: RequestProfileRules;
    onApply: (rules: RequestProfileRules) => void;
    onCancel: () => void;
}> = ({ current, onApply, onCancel }) => {
    const [draft, setDraft] = useState('');
    const areaRef = useRef<HTMLTextAreaElement | null>(null);
    const titleId = React.useId();
    const resultId = React.useId();
    const result = useMemo(() => checkRulesImport(draft, current), [draft, current]);
    const blank = !draft.trim();
    const cancelRef = useRef(onCancel);
    cancelRef.current = onCancel;

    useEffect(() => {
        const opener = document.activeElement;
        areaRef.current?.focus();
        const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') { e.stopPropagation(); cancelRef.current(); } };
        document.addEventListener('keydown', onKey);
        return () => {
            document.removeEventListener('keydown', onKey);
            if (opener instanceof HTMLElement && document.contains(opener)) opener.focus();
        };
    }, []);

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
            <div role="dialog" aria-modal="true" aria-labelledby={titleId}
                className="bg-raised border border-line rounded-lg shadow-2xl p-5 w-full max-w-2xl mx-4 space-y-3 max-h-[90vh] overflow-y-auto">
                <h3 id={titleId} className="text-base font-semibold text-ink">Paste request profile rules</h3>
                <p className="text-xs text-ink-muted">
                    An object with <code className="data-mono">subjectDnRules</code> and <code className="data-mono">sanRules</code>, as
                    "Copy as JSON" writes it. Apply replaces the rules in the form; nothing is saved until you Save.
                </p>
                <textarea ref={areaRef} rows={12} value={draft} onChange={(e) => setDraft(e.target.value)} spellCheck={false}
                    aria-label="Rules JSON to import" aria-describedby={resultId} aria-invalid={!blank && !result.ok}
                    className={`w-full data-mono px-3 py-2 rounded bg-raised border text-ink focus:outline-none ${!blank && !result.ok
                        ? 'border-crit focus:border-crit'
                        : 'border-line-strong focus:border-accent'}`} />
                <div id={resultId} aria-live="polite" className="text-xs space-y-2">
                    {blank ? null : !result.ok ? (
                        <p className="text-crit">{result.error}</p>
                    ) : (<>
                        <ul className="space-y-0.5 text-ink">
                            {result.summary.map((line) => <li key={line}>{line}</li>)}
                        </ul>
                        {result.unchanged && <p className="text-ink-muted">Identical to the rules in the form.</p>}
                        {result.warnings.length > 0 && (
                            <ul className="list-disc pl-4 space-y-0.5 text-warn">
                                {result.warnings.map((w) => <li key={w}>{w}</li>)}
                            </ul>
                        )}
                    </>)}
                </div>
                <div className="flex justify-end gap-3">
                    <button type="button" onClick={onCancel}
                        className="px-4 py-2 text-sm font-medium bg-raised border border-line-strong text-ink rounded hover:bg-hover transition-colors">
                        Cancel
                    </button>
                    <button type="button" disabled={!result.ok} onClick={() => { if (result.ok) onApply(result.rules); }}
                        className="px-4 py-2 text-sm font-medium bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50 transition-colors">
                        Apply
                    </button>
                </div>
            </div>
        </div>
    );
};

/** Subject DN and SAN rule editor for a request profile. */
export const RequestProfileRulesEditor: React.FC<Props> = ({ value, onChange }) => {
    /* ── subject DN rules ─────────────────────────────────────────────────── */
    const updateDnRule = (index: number, updates: Partial<SubjectDnFieldRule>) => {
        const next = [...value.subjectDnRules];
        next[index] = { ...next[index], ...updates };
        onChange({ ...value, subjectDnRules: next });
    };
    const addDnRule = () => onChange({ ...value, subjectDnRules: [...value.subjectDnRules, emptyDnRule()] });
    const removeDnRule = (index: number) => {
        const next = value.subjectDnRules.filter((_, i) => i !== index);
        // Never drop to zero rows: an empty table offers nothing to click and reads as broken.
        onChange({ ...value, subjectDnRules: next.length > 0 ? next : [emptyDnRule()] });
    };

    /* ── SAN rules ────────────────────────────────────────────────────────── */
    const toggleSanType = (type: string) => {
        const allowed = value.sanRules.allowedTypes.includes(type)
            ? value.sanRules.allowedTypes.filter((t) => t !== type)
            : [...value.sanRules.allowedTypes, type];
        onChange({ ...value, sanRules: { ...value.sanRules, allowedTypes: allowed } });
    };
    const updateSanRule = (type: string, updates: Partial<SanTypeRule>) => {
        const existing = value.sanRules.rules[type] ?? { regex: '', maxCount: DEFAULT_SAN_MAX_COUNT };
        onChange({
            ...value,
            sanRules: { ...value.sanRules, rules: { ...value.sanRules.rules, [type]: { ...existing, ...updates } } },
        });
    };

    return (
        <div className="space-y-4">
            {/* Subject DN rules */}
            <div>
                <div className="flex items-center justify-between mb-2">
                    <label className={labelClass}>Subject DN Rules</label>
                    <button type="button" onClick={addDnRule}
                        className="px-2 py-1 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors">
                        + Add Rule
                    </button>
                </div>
                <div className="bg-ground border border-line rounded overflow-x-auto">
                    <table className="w-full min-w-[600px] text-xs">
                        <thead>
                            <tr className="border-b border-line text-ink-muted">
                                <th className="px-2 py-2 text-left">Field</th>
                                <th className="px-2 py-2 text-left">Requirement</th>
                                <th className="px-2 py-2 text-left">Fixed Value</th>
                                <th className="px-2 py-2 text-left">Regex</th>
                                <th className="px-2 py-2 text-left">Max Length</th>
                                <th className="px-2 py-2 text-left">Default</th>
                                <th className="px-2 py-2"></th>
                            </tr>
                        </thead>
                        <tbody>
                            {value.subjectDnRules.map((rule, idx) => (
                                <tr key={idx} className="border-b border-line">
                                    <td className="px-2 py-1">
                                        <select value={rule.field} onChange={(e) => updateDnRule(idx, { field: e.target.value })} className={`${cellInput} w-16`}>
                                            {DN_FIELD_OPTIONS.map((f) => <option key={f} value={f}>{f}</option>)}
                                        </select>
                                    </td>
                                    <td className="px-2 py-1">
                                        <select value={rule.requirement} onChange={(e) => updateDnRule(idx, { requirement: e.target.value })} className={`${cellInput} w-24`}>
                                            {REQUIREMENT_OPTIONS.map((r) => <option key={r} value={r}>{r}</option>)}
                                        </select>
                                    </td>
                                    <td className="px-2 py-1">
                                        <input type="text" value={rule.fixedValue || ''} onChange={(e) => updateDnRule(idx, { fixedValue: e.target.value })}
                                            className={`${cellInput} w-24`} placeholder="Optional"
                                            title="When set, this value is always used and the requester cannot override it." />
                                    </td>
                                    <td className="px-2 py-1">
                                        <input type="text" value={rule.regex || ''} onChange={(e) => updateDnRule(idx, { regex: e.target.value })}
                                            className={`${cellInput} w-24`} placeholder="e.g. ^[a-z]+$" />
                                    </td>
                                    <td className="px-2 py-1">
                                        <input type="text" inputMode="numeric" value={rule.maxLength ?? ''}
                                            onChange={(e) => {
                                                const digits = e.target.value.replace(/[^0-9]/g, '');
                                                updateDnRule(idx, { maxLength: digits ? parseInt(digits, 10) : null });
                                            }}
                                            className={`${cellInput} w-16`} placeholder="64" />
                                    </td>
                                    <td className="px-2 py-1">
                                        <input type="text" value={rule.defaultValue || ''} onChange={(e) => updateDnRule(idx, { defaultValue: e.target.value })}
                                            className={`${cellInput} w-24`} placeholder="Optional"
                                            title="Used when the requester does not supply a value." />
                                    </td>
                                    <td className="px-2 py-1">
                                        <button type="button" onClick={() => removeDnRule(idx)} aria-label={`Remove ${rule.field} rule`}
                                            className="text-crit hover:text-crit text-xs px-1">
                                            X
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* SAN rules */}
            <div>
                <label className={labelClass}>SAN Rules</label>
                <div className="bg-ground border border-line rounded p-3 space-y-3">
                    <div>
                        <span className="text-xs text-ink-muted">Allowed Types</span>
                        <div className="flex flex-wrap gap-2 mt-1">
                            {SAN_TYPE_OPTIONS.map((type) => {
                                const active = value.sanRules.allowedTypes.includes(type);
                                return (
                                    <button key={type} type="button" onClick={() => toggleSanType(type)} aria-pressed={active}
                                        className={`px-2 py-1 text-xs rounded border transition-colors ${active
                                            ? 'bg-accent-soft text-accent-ink border-accent/40'
                                            : 'bg-ground text-ink-muted border-line hover:border-ink-faint'}`}>
                                        {type}
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    <label className="flex items-center gap-2 text-xs text-ink">
                        <input type="checkbox" checked={value.sanRules.required}
                            onChange={(e) => onChange({ ...value, sanRules: { ...value.sanRules, required: e.target.checked } })}
                            className="w-4 h-4 rounded" />
                        SAN Required
                    </label>

                    {/* Per-type constraints. Only rendered for permitted types — a regex on a type the
                        profile forbids is never consulted, and showing it invites the belief that it is. */}
                    {value.sanRules.allowedTypes.length > 0 && (
                        <div>
                            <span className="text-xs text-ink-muted">Per-Type Constraints</span>
                            <div className="overflow-x-auto mt-1">
                                <table className="w-full min-w-[420px] text-xs">
                                    <thead>
                                        <tr className="border-b border-line text-ink-muted">
                                            <th className="px-2 py-1.5 text-left">Type</th>
                                            <th className="px-2 py-1.5 text-left">Regex</th>
                                            <th className="px-2 py-1.5 text-left">Max Count</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {value.sanRules.allowedTypes.map((type) => {
                                            const rule = value.sanRules.rules[type];
                                            return (
                                                <tr key={type} className="border-b border-line">
                                                    <td className="px-2 py-1 text-ink">{type}</td>
                                                    <td className="px-2 py-1">
                                                        <input type="text" value={rule?.regex || ''} onChange={(e) => updateSanRule(type, { regex: e.target.value })}
                                                            className={`${cellInput} w-48`} placeholder="Any value"
                                                            aria-label={`${type} SAN regex`} />
                                                    </td>
                                                    <td className="px-2 py-1">
                                                        <input type="text" inputMode="numeric" value={rule?.maxCount ?? ''}
                                                            onChange={(e) => {
                                                                const digits = e.target.value.replace(/[^0-9]/g, '');
                                                                updateSanRule(type, { maxCount: digits ? parseInt(digits, 10) : DEFAULT_SAN_MAX_COUNT });
                                                            }}
                                                            className={`${cellInput} w-20`} placeholder={String(DEFAULT_SAN_MAX_COUNT)}
                                                            aria-label={`${type} SAN maximum count`} />
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            <RulesJsonActions value={value} onChange={onChange} />
        </div>
    );
};

export default RequestProfileRulesEditor;
