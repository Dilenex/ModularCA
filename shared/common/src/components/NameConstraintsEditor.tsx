import React from 'react';
import { FieldHint } from './forms';
import { TypedEntryListEditor, TypedEntryListView, type TypedEntry } from './TypedEntryListEditor';
import {
    NAME_CONSTRAINTS_CA_ONLY, NAME_CONSTRAINTS_HINT, NAME_CONSTRAINT_TYPES, nameConstraintListFromStored,
} from '../generalNames';

export interface NameConstraintsValue {
    permitted: TypedEntry[];
    excluded: TypedEntry[];
}

export interface NameConstraintsEditorProps extends NameConstraintsValue {
    onChange: (next: NameConstraintsValue) => void;
    /** Prefix for element ids. */
    idPrefix: string;
    disabled?: boolean;
}

const SECTIONS = [
    {
        key: 'permitted' as const,
        title: 'Permitted',
        hint: 'Names certificates under the CA may carry. Once any name of a type is listed, every name of that type must fall inside one.',
        add: '+ Add permitted name',
    },
    {
        key: 'excluded' as const,
        title: 'Excluded',
        hint: 'Names certificates under the CA may never carry, even inside a permitted subtree.',
        add: '+ Add excluded name',
    },
];

/**
 * The NameConstraints extension (RFC 5280 §4.2.1.10) edited as two typed lists, Permitted and
 * Excluded. Each row is a type (DNS, IP, Email, URI, DN) and a value checked the way the server's
 * `NameConstraintRules` checks it at save. Used by the signing profile form and by Create CA.
 */
export const NameConstraintsEditor: React.FC<NameConstraintsEditorProps> = ({ permitted, excluded, onChange, idPrefix, disabled }) => {
    const values = { permitted, excluded };
    return (
        <div className="space-y-3">
            <FieldHint id={`${idPrefix}-hint`}>{NAME_CONSTRAINTS_HINT}</FieldHint>
            <FieldHint id={`${idPrefix}-ca-only`}>{NAME_CONSTRAINTS_CA_ONLY}</FieldHint>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {SECTIONS.map((s) => (
                    <div key={s.key}>
                        <span id={`${idPrefix}-${s.key}-label`} className="block label-caps mb-1">{s.title}</span>
                        <p id={`${idPrefix}-${s.key}-hint`} className="mb-2 text-xs text-ink-muted">{s.hint}</p>
                        <TypedEntryListEditor
                            id={`${idPrefix}-${s.key}`}
                            aria-label={`${s.title} names`}
                            aria-describedby={`${idPrefix}-${s.key}-hint ${idPrefix}-hint`}
                            value={values[s.key]}
                            onChange={(rows) => onChange({ ...values, [s.key]: rows })}
                            types={NAME_CONSTRAINT_TYPES}
                            defaultType="DNS"
                            addLabel={s.add}
                            emptyText="None."
                            disabled={disabled}
                        />
                    </div>
                ))}
            </div>
        </div>
    );
};

/**
 * Name constraints for review, as stored (a JSON string, a list, or null): the permitted and
 * excluded subtrees with each entry's type, and any entry the server would refuse marked.
 */
export const NameConstraintsView: React.FC<{ permitted: unknown; excluded: unknown }> = ({ permitted, excluded }) => {
    const p = nameConstraintListFromStored(permitted);
    const x = nameConstraintListFromStored(excluded);
    if (p.length === 0 && x.length === 0) return <p className="text-xs text-ink-muted">None: the CA may issue for any name.</p>;
    return (
        <div className="space-y-2">
            <div>
                <span className="block text-xs text-ink-muted mb-1">Permitted</span>
                <TypedEntryListView entries={p} types={NAME_CONSTRAINT_TYPES} aria-label="Permitted names" />
            </div>
            <div>
                <span className="block text-xs text-ink-muted mb-1">Excluded</span>
                <TypedEntryListView entries={x} types={NAME_CONSTRAINT_TYPES} aria-label="Excluded names" />
            </div>
        </div>
    );
};

export default NameConstraintsEditor;
