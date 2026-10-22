import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { TAB_PARAM, activeKindTab, kindTabs, withKindTab, type KindTab } from '../pages/sshPlaces';

/**
 * The X.509 and SSH tabs of a page, read from and written to the address as the Profiles page
 * does (`?tab=SSH`). `tabs` holds only the tabs the reader can use, and `active` is the one the
 * address asks for when they have it, otherwise the first they have.
 */
export function useKindTabs(canUse: { x509: boolean; ssh: boolean }): { tabs: KindTab[]; active: KindTab | null; setActive: (tab: KindTab) => void } {
    const [searchParams, setSearchParams] = useSearchParams();
    const tabs = kindTabs(canUse);
    const active = activeKindTab(searchParams.get(TAB_PARAM), tabs);
    const setActive = (tab: KindTab) => setSearchParams(withKindTab(searchParams, tab), { replace: true });
    return { tabs, active, setActive };
}

/**
 * The tab strip of the Profiles page, for the X.509 and SSH tabs. A reader with no SSH tab sees
 * no strip: their page is as it was before SSH moved in.
 */
export const KindTabStrip: React.FC<{ tabs: readonly KindTab[]; active: KindTab | null; onChange: (tab: KindTab) => void }> = ({ tabs, active, onChange }) => {
    if (!tabs.includes('SSH')) return null;
    return (
        <div className="flex gap-1 border-b border-line overflow-x-auto">
            {tabs.map((tab) => (
                <button key={tab} type="button" onClick={() => onChange(tab)}
                    className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 whitespace-nowrap ${active === tab
                        ? 'text-accent-ink border-accent'
                        : 'text-ink-muted border-transparent hover:text-ink'}`}>
                    {tab}
                </button>
            ))}
        </div>
    );
};

/** The sentence an SSH tab shows in place of its content while the scope is confined to a space. */
export const SshScopeSentence: React.FC<{ text: string }> = ({ text }) => (
    <p role="status" className="text-sm text-ink max-w-3xl">{text}</p>
);
