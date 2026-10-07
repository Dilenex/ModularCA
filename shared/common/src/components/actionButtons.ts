/**
 * The buttons of a page's action bar. A bar holds neutral buttons, at most one primary, and its
 * destructive action last, in red. Colour is not used to tell ordinary actions apart.
 */
const base = 'px-3 py-1.5 text-xs font-medium rounded border transition-colors disabled:opacity-50 disabled:cursor-not-allowed';

export const actionButton = `${base} bg-raised text-ink border-line-strong hover:bg-hover`;
export const actionButtonPrimary = `${base} bg-accent text-on-accent border-accent hover:bg-accent-hover`;
export const actionButtonDanger = `${base} bg-crit-soft text-crit border-crit/40 hover:bg-crit/15`;

/** The "+ New" button at the right end of a table header's second line. */
export const toolbarButtonPrimary = 'px-2.5 py-1 text-xs font-medium rounded border border-accent bg-accent text-on-accent hover:bg-accent-hover transition-colors whitespace-nowrap disabled:opacity-50';
