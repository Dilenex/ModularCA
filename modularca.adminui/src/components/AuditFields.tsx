import React from 'react';
import { DetailField } from '@shared/components/cards/DetailField';
import { StructuredValue } from '@shared/components/StructuredValue';
import { parseJsonContainer } from '@shared/components/structuredValueModel';

const MONO_KEY = /id$|serial|hash|ip$/i;

/**
 * Every populated field of an audit row. Objects, and strings holding a JSON object or array
 * (`detailsJson`, ACME `identifiers`), render as nested rows across the full width.
 */
export const AuditFields: React.FC<{
    log: Record<string, unknown>;
    /** Keys (lower case) the caller renders itself. */
    omit?: ReadonlySet<string>;
    /** Extra classes for a structured field, e.g. a column span inside a grid. */
    wideClassName?: string;
}> = ({ log, omit, wideClassName = '' }) => (
    <>
        {Object.entries(log).filter(([k]) => !omit?.has(k.toLowerCase())).map(([k, v]) => {
            const structured = v !== null && typeof v === 'object' ? v : parseJsonContainer(v);
            if (structured) {
                return (
                    <div key={k} className={`py-1 ${wideClassName}`}>
                        <span className="label-caps">{k}</span>
                        <StructuredValue className="mt-1" value={structured} json={typeof v === 'string' ? v : undefined} />
                    </div>
                );
            }
            return <DetailField key={k} label={k} value={v == null ? '' : String(v)} mono={MONO_KEY.test(k)} />;
        })}
    </>
);
