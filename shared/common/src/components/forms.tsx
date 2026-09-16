import React from 'react';

/**
 * Form field primitives, shared by every SPA.
 *
 * Twenty-one files across adminui and userui each declared their own `inputClass`, in ten distinct
 * variants. They disagreed about the field background (`gray-50/900`, `gray-100/800`,
 * `gray-200/700`), the border weight (`gray-300/700` vs `gray-400/600`), and whether placeholders
 * and disabled states were styled at all — so a form's appearance depended on which file it
 * happened to live in, and a user moving between two pages of the same application saw two
 * different-looking inputs.
 *
 * The values below are the majority spelling of each, so most call sites are unchanged. The
 * placeholder and disabled rules are folded into the base rather than left optional: they are
 * additive, they have no effect on a field that has neither, and their absence was never a
 * decision anyone made.
 */

/**
 * Text inputs, selects and textareas.
 *
 * `w-full` is included — the one call site that deliberately sized its own field is the search box
 * in `MyCertificates`, which composes with `inputClassNarrow`.
 */
export const inputClass =
    'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 ' +
    'rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 ' +
    'focus:outline-none focus:border-blue-500 disabled:opacity-50';

/** Same, without `w-full`, for a field sized by its container. */
export const inputClassNarrow = inputClass.replace('w-full ', '');

/**
 * Field labels.
 *
 * `font-semibold` was present in ten of the eighteen label declarations and absent from eight;
 * the majority wins so the label weight stops changing from page to page.
 */
export const labelClass = 'block text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1';

/**
 * Helper text under a field: what a value means or what saving it does, visible without hovering.
 *
 * The console carried 157 distinct native `title` tooltips and no hint primitive. Hover text is
 * invisible on touch, delayed, unstyled and unsearchable, so explanations of consequence (what a
 * revocation reason does, that an empty ceiling means unrestricted) were effectively hidden. This
 * is the one place such text should go; pass `id` and reference it from the control's
 * `aria-describedby` so assistive technology reads it too.
 */
export const FieldHint: React.FC<{ id?: string; tone?: 'muted' | 'warn'; className?: string; children: React.ReactNode }> = ({ id, tone = 'muted', className = '', children }) => (
    <p id={id} className={`mt-1 text-[11px] leading-snug ${tone === 'warn' ? 'text-amber-800 dark:text-amber-300' : 'text-gray-500 dark:text-gray-400'} ${className}`}>
        {children}
    </p>
);

/**
 * A small (i) that shows an explanation on hover and on keyboard focus.
 *
 * For places where visible helper text would cost too much room, such as the top bar. The text is
 * still in the document (visually hidden until shown) and referenced through `aria-describedby`,
 * so it reads to assistive technology without hovering. Prefer `FieldHint` inside forms, where
 * there is room to just say the thing.
 */
export const InfoTip: React.FC<{ text: React.ReactNode; label?: string; className?: string; align?: 'left' | 'right' }> = ({ text, label = 'More information', className = '', align = 'left' }) => {
    const id = React.useId();
    return (
        <span className={`relative inline-flex group ${className}`}>
            <button
                type="button"
                aria-label={label}
                aria-describedby={id}
                className="inline-flex items-center justify-center w-4 h-4 rounded-full border border-gray-400 dark:border-gray-500 text-[10px] leading-none font-semibold text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 cursor-help select-none"
            >
                i
            </button>
            <span
                role="tooltip"
                id={id}
                className={`pointer-events-none absolute top-full mt-1.5 z-50 w-72 max-w-[80vw] rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-[11px] leading-snug text-left font-normal text-gray-700 dark:text-gray-200 shadow-lg opacity-0 invisible transition-opacity duration-100 group-hover:opacity-100 group-hover:visible group-focus-within:opacity-100 group-focus-within:visible ${align === 'right' ? 'right-0' : 'left-0'}`}
            >
                {text}
            </span>
        </span>
    );
};

/**
 * Labelled on/off switch.
 *
 * Two copies lived inside adminui alone — `LdapPublisherDetail` and `ProtocolConfig` — which is
 * the same drift this module exists to stop, at a smaller scale. They render the same control at
 * different sizes and with the label on opposite sides, so both layouts survive as props rather
 * than one being imposed on the other: this is a deduplication, not a redesign, and neither page
 * should look different afterwards.
 *
 * ProtocolConfig's copy also declared a `selectClass` prop it never read. Dropped.
 */
export const ToggleField: React.FC<{
    label: string;
    checked: boolean;
    onChange: (v: boolean) => void;
    /** Rendered under the label in both layouts. */
    description?: React.ReactNode;
    /** `sm` is the compact inline switch; `md` is the settings-row switch. */
    size?: 'sm' | 'md';
    /** `right` puts the label after the switch (compact); `left` puts it before (settings row). */
    labelSide?: 'left' | 'right';
    disabled?: boolean;
}> = ({ label, checked, onChange, description, size = 'sm', labelSide = 'right', disabled = false }) => {
    const track = size === 'md' ? 'w-11 h-6' : 'w-8 h-4';
    const knob = size === 'md' ? 'w-5 h-5' : 'w-3 h-3';
    const shift = size === 'md' ? 'translate-x-5' : 'translate-x-4';
    const id = React.useId();
    const descId = description ? `${id}-desc` : undefined;
    const flip = () => { if (!disabled) onChange(!checked); };

    // A real button: reachable by keyboard, announced as a switch, and toggled by the label text
    // as well as the track. The previous div-with-onClick was none of those.
    const toggle = (
        <button
            type="button"
            role="switch"
            aria-checked={checked}
            aria-labelledby={`${id}-label`}
            aria-describedby={descId}
            disabled={disabled}
            onClick={flip}
            className={`relative shrink-0 ${track} rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-1 ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'} ${checked ? 'bg-blue-600' : 'bg-gray-400 dark:bg-gray-600'}`}
        >
            <span className={`absolute top-0.5 left-0.5 ${knob} rounded-full bg-white shadow transition-transform ${checked ? shift : ''}`} />
        </button>
    );

    const text = (
        <span id={`${id}-label`} onClick={flip} className={`${disabled ? '' : 'cursor-pointer'} ${labelSide === 'left' ? 'text-xs text-gray-700 dark:text-gray-300' : 'text-gray-700 dark:text-gray-300'}`}>{label}</span>
    );
    const desc = description
        ? <p id={descId} className={`${labelSide === 'left' ? 'text-[10px]' : 'text-[11px]'} text-gray-600 dark:text-gray-400`}>{description}</p>
        : null;

    if (labelSide === 'left') {
        return (
            <div className="flex items-center justify-between gap-3 py-1">
                <div className="min-w-0">
                    {text}
                    {desc}
                </div>
                {toggle}
            </div>
        );
    }

    return (
        <div className="text-sm">
            <div className="flex items-center gap-2">
                {toggle}
                {text}
            </div>
            {desc && <div className="pl-10">{desc}</div>}
        </div>
    );
};
