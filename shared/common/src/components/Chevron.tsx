import React from 'react';

/**
 * Shared because all three consuming SPAs rendered the identical component and any change to
 * the glyph — the reason it exists at all — had to be made three times to stay consistent.
 */

export type ChevronDirection = 'right' | 'down' | 'up' | 'left';

const ROTATION: Record<ChevronDirection, string> = {
    right: 'rotate-0',
    down: 'rotate-90',
    left: 'rotate-180',
    up: '-rotate-90',
};

export interface ChevronProps {
    /** Which way the chevron points. Ignored when `open` is provided. */
    direction?: ChevronDirection;
    /** Convenience for expand/collapse: points down when open, right when closed. */
    open?: boolean;
    /** Sizing/colour utility classes. Defaults to a small chevron in the inherited text colour. */
    className?: string;
}

/**
 * Inline-SVG chevron for expand/collapse and dropdown affordances. Replaces the ▶/▼/▲ glyphs,
 * which some OSes (notably Windows) render as colour emoji with a boxed background. Strokes in
 * currentColor so it follows the surrounding text colour unless a `text-*` class is passed.
 */
export const Chevron: React.FC<ChevronProps> = ({ direction, open, className = 'w-3 h-3' }) => {
    const dir: ChevronDirection = open === undefined ? (direction ?? 'right') : open ? 'down' : 'right';
    return (
        <svg viewBox="0 0 12 12" aria-hidden="true"
            className={`inline-block shrink-0 transition-transform ${ROTATION[dir]} ${className}`}
            fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M4 2.5 L8 6 L4 9.5" />
        </svg>
    );
};
