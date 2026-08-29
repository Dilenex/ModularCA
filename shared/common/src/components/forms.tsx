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
    /** Rendered under the label. Only the wide variant has room for it. */
    description?: string;
    /** `sm` is the compact inline switch; `md` is the settings-row switch. */
    size?: 'sm' | 'md';
    /** `right` puts the label after the switch (compact); `left` puts it before (settings row). */
    labelSide?: 'left' | 'right';
}> = ({ label, checked, onChange, description, size = 'sm', labelSide = 'right' }) => {
    const track = size === 'md' ? 'w-11 h-6' : 'w-8 h-4';
    const knob = size === 'md' ? 'w-5 h-5' : 'w-3 h-3';
    const shift = size === 'md' ? 'translate-x-5' : 'translate-x-4';

    const toggle = (
        <div
            onClick={() => onChange(!checked)}
            className={`relative ${track} rounded-full transition-colors cursor-pointer ${checked ? 'bg-blue-600' : 'bg-gray-400 dark:bg-gray-600'}`}
        >
            <div className={`absolute top-0.5 left-0.5 ${knob} rounded-full bg-white shadow transition-transform ${checked ? shift : ''}`} />
        </div>
    );

    if (labelSide === 'left') {
        return (
            <div className="flex items-center justify-between py-1">
                <div>
                    <span className="text-xs text-gray-700 dark:text-gray-300">{label}</span>
                    {description && <p className="text-[10px] text-gray-600 dark:text-gray-400">{description}</p>}
                </div>
                {toggle}
            </div>
        );
    }

    return (
        <label className="flex items-center gap-2 cursor-pointer text-sm">
            {toggle}
            <span className="text-gray-700 dark:text-gray-300">{label}</span>
        </label>
    );
};
