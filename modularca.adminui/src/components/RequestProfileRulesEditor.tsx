import React, { useEffect, useMemo, useState } from 'react';
import { labelClass } from '@shared/components/forms';

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
 * The JSON escape hatch stays anyway, collapsed. Not for the per-type rules any more, but because
 * a request profile is a policy object an operator may need to paste between environments, diff
 * against a colleague's, or populate with a field this UI has not learned about yet. Removing the
 * only way to do any of that would trade one kind of stuck for another.
 */

import {
    DN_FIELD_OPTIONS, REQUIREMENT_OPTIONS, SAN_TYPE_OPTIONS, DEFAULT_SAN_MAX_COUNT,
    emptyDnRule, emptySanRules, emptyRules, parseRules, serializeRules,
    type RequestProfileRules, type SanRulesModel, type SanTypeRule, type SubjectDnFieldRule,
} from './requestProfileRules';

export {
    emptyDnRule, emptySanRules, emptyRules, parseRules, serializeRules,
    type RequestProfileRules, type SanRulesModel, type SanTypeRule, type SubjectDnFieldRule,
};

const cellInput = 'bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-1 py-1 text-gray-900 dark:text-white text-xs';

interface Props {
    value: RequestProfileRules;
    onChange: (next: RequestProfileRules) => void;
    /**
     * Reports whether the JSON escape hatch currently holds something unparseable, so the page can
     * disable its save button. Without this the page would save the last *valid* value while the
     * operator looks at the invalid text they typed, which is the worst of both.
     */
    onErrorChange?: (error: string | null) => void;
}

/** Subject DN and SAN rule editor for a request profile. */
export const RequestProfileRulesEditor: React.FC<Props> = ({ value, onChange, onErrorChange }) => {
    const [jsonOpen, setJsonOpen] = useState(false);
    const [jsonDraft, setJsonDraft] = useState('');
    const [jsonError, setJsonError] = useState<string | null>(null);

    const serialized = useMemo(() => JSON.stringify(serializeRules(value), null, 2), [value]);

    // Opening the hatch seeds it from the structured state; while it is closed the draft is never
    // authoritative, so a stale one cannot resurrect an old value when it reopens.
    useEffect(() => {
        if (jsonOpen) { setJsonDraft(serialized); setJsonError(null); onErrorChange?.(null); }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [jsonOpen]);

    useEffect(() => () => onErrorChange?.(null), []); // eslint-disable-line react-hooks/exhaustive-deps

    const applyJson = (text: string) => {
        setJsonDraft(text);
        try {
            const parsed = JSON.parse(text);
            if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
                throw new Error('Expected an object with subjectDnRules and sanRules.');
            }
            onChange(parseRules(parsed));
            setJsonError(null);
            onErrorChange?.(null);
        } catch (err: any) {
            const message = err?.message || 'Invalid JSON';
            setJsonError(message);
            onErrorChange?.(message);
        }
    };

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
                        className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                        + Add Rule
                    </button>
                </div>
                <div className="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded overflow-x-auto">
                    <table className="w-full min-w-[600px] text-xs">
                        <thead>
                            <tr className="border-b border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400">
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
                                <tr key={idx} className="border-b border-gray-200 dark:border-gray-800">
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
                                            className="text-red-800 dark:text-red-400 hover:text-red-600 dark:hover:text-red-300 text-xs px-1">
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
                <div className="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-3 space-y-3">
                    <div>
                        <span className="text-xs text-gray-600 dark:text-gray-400">Allowed Types</span>
                        <div className="flex flex-wrap gap-2 mt-1">
                            {SAN_TYPE_OPTIONS.map((type) => {
                                const active = value.sanRules.allowedTypes.includes(type);
                                return (
                                    <button key={type} type="button" onClick={() => toggleSanType(type)} aria-pressed={active}
                                        className={`px-2 py-1 text-xs rounded border transition-colors ${active
                                            ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700'
                                            : 'bg-gray-50 dark:bg-gray-900 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-700 hover:border-gray-500'}`}>
                                        {type}
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                        <input type="checkbox" checked={value.sanRules.required}
                            onChange={(e) => onChange({ ...value, sanRules: { ...value.sanRules, required: e.target.checked } })}
                            className="w-4 h-4 rounded" />
                        SAN Required
                    </label>

                    {/* Per-type constraints. Only rendered for permitted types — a regex on a type the
                        profile forbids is never consulted, and showing it invites the belief that it is. */}
                    {value.sanRules.allowedTypes.length > 0 && (
                        <div>
                            <span className="text-xs text-gray-600 dark:text-gray-400">Per-Type Constraints</span>
                            <div className="overflow-x-auto mt-1">
                                <table className="w-full min-w-[420px] text-xs">
                                    <thead>
                                        <tr className="border-b border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400">
                                            <th className="px-2 py-1.5 text-left">Type</th>
                                            <th className="px-2 py-1.5 text-left">Regex</th>
                                            <th className="px-2 py-1.5 text-left">Max Count</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {value.sanRules.allowedTypes.map((type) => {
                                            const rule = value.sanRules.rules[type];
                                            return (
                                                <tr key={type} className="border-b border-gray-200 dark:border-gray-800">
                                                    <td className="px-2 py-1 text-gray-800 dark:text-gray-200">{type}</td>
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

            {/* JSON escape hatch */}
            <div>
                <button type="button" onClick={() => setJsonOpen(!jsonOpen)} aria-expanded={jsonOpen}
                    className="text-xs text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 transition-colors">
                    {jsonOpen ? '▾' : '▸'} Advanced (JSON)
                </button>
                {jsonOpen && (
                    <div className="mt-2 space-y-1">
                        <textarea rows={12} value={jsonDraft} onChange={(e) => applyJson(e.target.value)} spellCheck={false}
                            aria-label="Request profile rules as JSON"
                            className={`w-full font-mono text-xs px-3 py-2 rounded bg-gray-50 dark:bg-gray-900 border text-gray-900 dark:text-white focus:outline-none ${jsonError
                                ? 'border-red-400 dark:border-red-700 focus:border-red-500'
                                : 'border-gray-300 dark:border-gray-700 focus:border-blue-500'}`} />
                        {jsonError
                            ? <p className="text-xs text-red-700 dark:text-red-400">{jsonError}</p>
                            : <p className="text-xs text-gray-500 dark:text-gray-500">Edits here update the fields above as you type.</p>}
                    </div>
                )}
            </div>
        </div>
    );
};

export default RequestProfileRulesEditor;
