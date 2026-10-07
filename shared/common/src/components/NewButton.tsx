import React from 'react';
import { toolbarButtonPrimary } from './actionButtons';

interface NewButtonProps {
    /** What it makes, in lower case: "user", "trust anchor". Read out and shown as the tooltip. */
    what?: string;
    /** The verb, where "New" would mislead: "Import", "Bind", "Sign key". */
    label?: string;
    /** The form this button opens is showing, so the button now closes it. */
    open?: boolean;
    disabled?: boolean;
    onClick: () => void;
}

/** The create button a table carries in its header (DataTable's toolbarAction): "+ New", or Cancel while its form is open. */
export const NewButton: React.FC<NewButtonProps> = ({ what, label = 'New', open, disabled, onClick }) => {
    const full = [label, what].filter(Boolean).join(' ');
    return (
        <button type="button" onClick={onClick} disabled={disabled} className={toolbarButtonPrimary}
            title={full} aria-label={open ? 'Cancel' : full}>
            {open ? 'Cancel' : `+ ${label}`}
        </button>
    );
};

export default NewButton;
