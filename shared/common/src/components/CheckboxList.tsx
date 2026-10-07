import React from 'react';
import { labelClass } from './forms';
import {
    type CeilingMode, type CheckboxGroup, type CheckboxOption, ceilingEmptyOnly, ceilingModeOf, flattenGroups, toggleValue, unknownValues,
} from './checkboxListModel';

export type { CheckboxGroup, CheckboxOption, CeilingMode } from './checkboxListModel';

export const checkboxInputClass = 'mt-0.5 h-4 w-4 shrink-0 rounded border-line-strong accent-accent disabled:cursor-not-allowed';
export const radioInputClass = 'h-4 w-4 shrink-0 accent-accent';

export interface FieldProblem {
    tone: 'crit' | 'warn' | 'info';
    message: React.ReactNode;
}

const TONE_CLASS: Record<FieldProblem['tone'], string> = {
    crit: 'text-crit', warn: 'text-warn', info: 'text-ink-muted',
};

/** Problem lines under a field; each gets an id so the control can point at it. */
export const ProblemList: React.FC<{ id: string; problems: FieldProblem[] }> = ({ id, problems }) => {
    if (problems.length === 0) return null;
    return (
        <ul id={id} className="mt-1 space-y-0.5 text-xs" aria-live="polite">
            {problems.map((p, i) => <li key={i} className={TONE_CLASS[p.tone]}>{p.message}</li>)}
        </ul>
    );
};

const GRID: Record<1 | 2 | 3, string> = {
    1: 'grid grid-cols-1 gap-y-1.5',
    2: 'grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5',
    3: 'grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-1.5',
};

const BADGE_CLASS: Record<NonNullable<CheckboxOption['badge']>['tone'], string> = {
    ok: 'bg-ok-soft text-ok border-ok/40',
    warn: 'bg-warn-soft text-warn border-warn/40',
    muted: 'bg-sunken text-ink-muted border-line-strong',
};

/** One labelled checkbox; the whole label is the click target. */
export const CheckboxRow: React.FC<{
    option: CheckboxOption;
    checked: boolean;
    onChange: (on: boolean) => void;
    disabled?: boolean;
}> = ({ option: o, checked, onChange, disabled }) => {
    const off = disabled || o.disabled;
    return (
        <label className={`flex items-start gap-2 ${off ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}`} title={o.disabled ? o.disabledReason : undefined}>
            <input type="checkbox" className={checkboxInputClass} checked={checked} disabled={off}
                onChange={(e) => onChange(e.target.checked)} />
            <span className="min-w-0">
                <span className={`text-sm ${o.tone === 'warn' ? 'text-warn' : 'text-ink'}`}>{o.label}</span>
                {o.badge && <span className={`ml-1.5 inline-block px-1.5 py-px rounded border text-[10px] font-semibold align-middle ${BADGE_CLASS[o.badge.tone]}`}>{o.badge.label}</span>}
                {o.detail && <span className="ml-1.5 font-mono text-[11px] text-ink-muted">{o.detail}</span>}
                {o.description && <span className="block text-xs text-ink-muted">{o.description}</span>}
                {o.disabled && o.disabledReason && <span className="sr-only"> ({o.disabledReason})</span>}
            </span>
        </label>
    );
};

export interface CheckboxListProps {
    /** The field name, rendered as the fieldset legend. */
    legend: React.ReactNode;
    value: string[];
    onChange: (next: string[]) => void;
    /** Flat options; pass `groups` instead for a grouped list. */
    options?: readonly CheckboxOption[];
    groups?: readonly CheckboxGroup[];
    /**
     * Makes the list a ceiling: an "Any / Only these" radio pair, where Any saves an empty list.
     * Leave out for lists whose values are written as-is (an empty list then means none).
     */
    ceiling?: { anyLabel: string; onlyLabel?: string };
    /**
     * The ceiling mode, when the form keeps it (so it can block Save on Only these with nothing
     * ticked, and save Any as an empty list). Left out, the list tracks the mode itself and Any
     * clears the value.
     */
    mode?: CeilingMode;
    onModeChange?: (mode: CeilingMode) => void;
    hint?: React.ReactNode;
    problems?: FieldProblem[];
    columns?: 1 | 2 | 3;
    id?: string;
    disabled?: boolean;
    /**
     * How stored values no option offers are introduced and shown. Default: "Also stored, not
     * offered above, kept as is:" with each value verbatim.
     */
    unknown?: { label: React.ReactNode; format?: (value: string) => string; tone?: 'crit' };
}

/// <summary>
/// A list of checkboxes in a fieldset, flat or grouped, optionally behind an Any / Only these
/// switch. Values no option offers are listed and kept rather than dropped, and can be removed.
/// </summary>
export const CheckboxList: React.FC<CheckboxListProps> = ({
    legend, value, onChange, options, groups, ceiling, mode: controlledMode, onModeChange, hint, problems = [], columns = 2, id, disabled, unknown: unknownDisplay,
}) => {
    const autoId = React.useId();
    const baseId = id ?? autoId;
    const hintId = `${baseId}-hint`;
    const problemsId = `${baseId}-problems`;

    const [onlyChosen, setOnlyChosen] = React.useState(value.length > 0);
    const lastSelection = React.useRef<string[]>(value);
    if (value.length > 0) lastSelection.current = value;
    const controlled = controlledMode !== undefined && !!onModeChange;
    const mode = !ceiling ? 'only' : controlled ? controlledMode! : ceilingModeOf(value, onlyChosen);

    const all = groups ? flattenGroups(groups) : [...(options ?? [])];
    const unknown = unknownValues(value, all);

    const shown: FieldProblem[] = [...problems];
    if (ceiling && ceilingEmptyOnly(mode, value)) {
        shown.unshift({ tone: 'crit', message: `Nothing is ticked, so this saves as “${ceiling.anyLabel}”. Tick at least one, or choose ${ceiling.anyLabel}.` });
    }
    const describedBy = [hint ? hintId : null, shown.length ? problemsId : null].filter(Boolean).join(' ') || undefined;

    const chooseMode = (next: CeilingMode) => {
        if (controlled) { onModeChange!(next); return; }
        if (next === 'any') { setOnlyChosen(false); if (value.length) onChange([]); return; }
        setOnlyChosen(true);
        if (value.length === 0 && lastSelection.current.length) onChange(lastSelection.current);
    };

    const rows = (opts: readonly CheckboxOption[]) => (
        <div className={GRID[columns]}>
            {opts.map((o) => (
                <CheckboxRow key={o.value} option={o} checked={value.includes(o.value)} disabled={disabled}
                    onChange={(on) => onChange(toggleValue(value, o.value, on))} />
            ))}
        </div>
    );

    return (
        <fieldset id={baseId} aria-describedby={describedBy} className="min-w-0">
            <legend className={labelClass}>{legend}</legend>
            {ceiling && (
                <div role="radiogroup" aria-label={typeof legend === 'string' ? legend : undefined} className="flex flex-wrap gap-x-5 gap-y-1 mb-2 text-sm text-ink">
                    <label className="flex items-center gap-2 cursor-pointer">
                        <input type="radio" name={`${baseId}-mode`} className={radioInputClass} checked={mode === 'any'} disabled={disabled} onChange={() => chooseMode('any')} />
                        {ceiling.anyLabel}
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                        <input type="radio" name={`${baseId}-mode`} className={radioInputClass} checked={mode === 'only'} disabled={disabled} onChange={() => chooseMode('only')} />
                        {ceiling.onlyLabel ?? 'Only these'}
                    </label>
                </div>
            )}
            {mode === 'only' && (groups ? (
                <div className="space-y-2">
                    {groups.filter((g) => g.options.length > 0).map((g) => (
                        <fieldset key={g.id} className="min-w-0">
                            <legend className="text-xs font-medium text-ink-muted mb-1">{g.label}</legend>
                            {rows(g.options)}
                        </fieldset>
                    ))}
                </div>
            ) : rows(all))}
            {mode === 'only' && unknown.length > 0 && (
                <div className={`mt-2 flex flex-wrap items-center gap-1.5 text-xs ${unknownDisplay?.tone === 'crit' ? 'text-crit' : 'text-ink-muted'}`}>
                    <span>{unknownDisplay?.label ?? 'Also stored, not offered above, kept as is:'}</span>
                    {unknown.map((v) => (
                        <span key={v} className={`inline-flex items-center gap-1 rounded border bg-sunken px-1.5 py-0.5 font-mono text-ink ${unknownDisplay?.tone === 'crit' ? 'border-crit' : 'border-line'}`}>
                            {unknownDisplay?.format ? unknownDisplay.format(v) : v}
                            {!disabled && (
                                <button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(value.filter((x) => x !== v))}
                                    className="text-ink-muted hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded">×</button>
                            )}
                        </span>
                    ))}
                </div>
            )}
            {hint && <p id={hintId} className="mt-1 text-xs text-ink-muted">{hint}</p>}
            <ProblemList id={problemsId} problems={shown} />
        </fieldset>
    );
};

/** CheckboxList with its options in labelled groups. */
export const GroupedCheckboxList: React.FC<Omit<CheckboxListProps, 'options'> & { groups: readonly CheckboxGroup[] }> = (props) =>
    <CheckboxList {...props} />;

export default CheckboxList;
