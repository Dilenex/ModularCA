import React from 'react';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { GroupedCheckboxList } from '@shared/components/CheckboxList';
import { SSH_EXTENSION_OPTIONS, SSH_REQUIRED_EXTENSIONS_HINT } from '../profileHelpers';
import { groupSshExtensions } from './pickerCatalogs';
import { type ProfileFormMode, sshRequiredNotAllowed } from './profileFormCore';
import { ChipListInput } from '@shared/components/ChipListInput';
import { validateRegex } from '@shared/validators';
import { type SshCertProfileFormState, effectiveAllowed, matchPrincipal } from './sshCertProfile';

/** Tries a login name or hostname against the patterns being edited and shows which of them match. */
const PrincipalTester: React.FC<{ patterns: string[] }> = ({ patterns }) => {
    const [principal, setPrincipal] = React.useState('');
    const results = principal ? matchPrincipal(principal, patterns) : [];
    const allowed = patterns.length === 0 || results.some((r) => r.result === 'match');
    return (
        <div className="mt-2 rounded border border-line bg-sunken p-2 space-y-1.5">
            <label htmlFor="ssh-cp-principal-test" className="block text-xs text-ink-muted">Test a login name or hostname</label>
            <input id="ssh-cp-principal-test" type="text" value={principal} onChange={(e) => setPrincipal(e.target.value)}
                className={`${inputClass} font-mono`} placeholder="e.g. alice" autoComplete="off" spellCheck={false} />
            {principal && (
                <div className="text-xs space-y-0.5" role="status">
                    <p className={allowed ? 'text-ok' : 'text-crit'}>
                        {patterns.length === 0 ? 'Inside the limit: with no patterns there is no outer limit.' : allowed ? 'Inside the limit: at least one pattern matches.' : 'Outside the limit: no pattern matches, so a request that names it is refused.'}
                    </p>
                    {results.length > 0 && (
                        <ul className="space-y-0.5">
                            {results.map((r, i) => (
                                <li key={`${r.pattern}-${i}`} className="flex gap-2">
                                    <span className={`w-16 shrink-0 ${r.result === 'match' ? 'text-ok' : r.result === 'invalid' ? 'text-crit' : 'text-ink-muted'}`}>
                                        {r.result === 'match' ? 'matches' : r.result === 'invalid' ? 'invalid' : 'no match'}
                                    </span>
                                    <span className="font-mono text-ink break-all">{r.pattern}</span>
                                </li>
                            ))}
                        </ul>
                    )}
                    <p className="text-ink-muted">Checked with the browser's regex engine; the server uses .NET regex, which can differ on unusual syntax.</p>
                </div>
            )}
        </div>
    );
};

/**
 * What each OpenSSH certificate extension does, shown under each checkbox. A certificate carries
 * exactly the `permit-*` extensions its profiles and request name. A `no-*` name adds nothing to
 * a certificate: it withholds the matching `permit-*`, even where the same list names it.
 */
const SSH_EXTENSION_HELP: Record<string, string> = {
    'permit-pty': 'Allows the session to allocate a pseudo-terminal. Without it the user gets no interactive shell, only non-interactive commands.',
    'permit-port-forwarding': 'Allows -L, -R and -D tunnels, so the certificate holder can reach other hosts through the server.',
    'permit-agent-forwarding': 'Allows the user\'s ssh-agent to be forwarded to the server, where root could use their keys while the session lasts.',
    'permit-X11-forwarding': 'Allows X11 display forwarding from the server back to the client.',
    'permit-user-rc': 'Allows ~/.ssh/rc on the server to run at login, a common persistence spot.',
    'no-touch-required': 'For FIDO/U2F security-key certificates: the server does not demand a physical touch on each authentication.',
    'no-pty': 'Withholds permit-pty, even when it is also named: the certificate cannot open an interactive shell. Adds nothing to the certificate.',
    'no-port-forwarding': 'Withholds permit-port-forwarding, even when it is also named: no tunnels through the server. Adds nothing to the certificate.',
    'no-agent-forwarding': 'Withholds permit-agent-forwarding, even when it is also named: the user\'s agent is never exposed to the server. Adds nothing to the certificate.',
    'no-X11-forwarding': 'Withholds permit-X11-forwarding, even when it is also named. Adds nothing to the certificate.',
    'no-user-rc': 'Withholds permit-user-rc, even when it is also named: ~/.ssh/rc is not executed at login. Adds nothing to the certificate.',
};
const extensionHelp = (ext: string): string => SSH_EXTENSION_HELP[ext] || `OpenSSH extension ${ext}.`;

/** Shown above the two extension pickers. */
const EXACT_EXTENSIONS_HINT = 'A certificate carries exactly the extensions named for it: the signing profile\'s default extensions, or the ones the request names instead, plus the required extensions below. None is added by default. A certificate with no permit-* extension allows no terminal, no forwarding and no ~/.ssh/rc. The names under Withhold put nothing into a certificate; each only withholds the permit-* of the same name.';

/// <summary>
/// The SSH cert profile fields, used unchanged by the new-profile page and the edit view.
/// Nothing is read-only in edit mode: the server accepts every field on update.
/// </summary>
export const SshCertProfileForm: React.FC<{
    value: SshCertProfileFormState;
    onChange: (next: SshCertProfileFormState) => void;
    mode: ProfileFormMode;
}> = ({ value: f, onChange }) => {
    const set = <K extends keyof SshCertProfileFormState>(key: K, v: SshCertProfileFormState[K]) => onChange({ ...f, [key]: v });
    const conflicts = sshRequiredNotAllowed(f.requiredExtensions, effectiveAllowed(f));
    return (
        <div className="space-y-3 max-w-3xl">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div><label className={labelClass}>Name</label><input type="text" value={f.name} onChange={(e) => set('name', e.target.value)} className={inputClass} placeholder="e.g. Standard User Cert" /></div>
                <div><label className={labelClass}>Description</label><input type="text" value={f.description} onChange={(e) => set('description', e.target.value)} className={inputClass} placeholder="Optional" /></div>
                <div><label className={labelClass}>Most login names on a certificate</label><input type="text" inputMode="numeric" value={f.maxPrincipals} onChange={(e) => set('maxPrincipals', e.target.value.replace(/\D/g, ''))} className={inputClass} aria-describedby="ssh-cp-principals-max-hint" />
                    <FieldHint id="ssh-cp-principals-max-hint">For a host certificate, the most hostnames. Blank or 0 falls back to 10.</FieldHint>
                </div>
                <div>
                    <label className={labelClass}>Max Validity (hours)</label>
                    <input type="text" inputMode="numeric" value={f.maxValidityHours} onChange={(e) => set('maxValidityHours', e.target.value.replace(/\D/g, ''))} className={inputClass} aria-describedby="ssh-cp-validity-hint" />
                    <FieldHint id="ssh-cp-validity-hint">Whole hours, not an ISO 8601 duration: 720 is thirty days. Blank or 0 falls back to 720. A request asking for longer is refused.</FieldHint>
                </div>
            </div>
            <div>
                <label htmlFor="ssh-cp-principals" className={labelClass}>Login name patterns (the outer limit)</label>
                {/* Commas are legal inside a regex ({0,31}), so they do not separate entries here. */}
                <ChipListInput id="ssh-cp-principals" value={f.allowedPrincipalPatterns} onChange={(next) => set('allowedPrincipalPatterns', next)}
                    validate={validateRegex} commaSeparates={false} mono placeholder="e.g. ^[a-z_][a-z0-9_-]*$, then Enter" aria-describedby="ssh-cp-principals-hint" />
                <FieldHint id="ssh-cp-principals-hint">The outer limit on the login names a certificate from this profile may carry, and on the hostnames of a host certificate. One regular expression per entry; every name asked for must match at least one. A pattern grants nothing: who may use which login name is set on the SSH CA key, under Login names. Leave empty for no outer limit; this is a ceiling, so no patterns means unrestricted, not none. A login name is the SSH principal.</FieldHint>
                <PrincipalTester patterns={f.allowedPrincipalPatterns} />
            </div>
            <FieldHint>{EXACT_EXTENSIONS_HINT}</FieldHint>
            <GroupedCheckboxList id="ssh-cp-allowed-ext" legend="Allowed Extensions" value={f.allowedExtensions} onChange={(next) => set('allowedExtensions', next)}
                groups={groupSshExtensions(SSH_EXTENSION_OPTIONS, extensionHelp)} ceiling={{ anyLabel: 'Any extension' }}
                mode={f.allowedExtensionsMode} onModeChange={(m) => set('allowedExtensionsMode', m)}
                hint="A ceiling on the extensions a request may name. Any leaves the list empty, which the server reads as unrestricted." />
            <GroupedCheckboxList id="ssh-cp-required-ext" legend="Required Extensions" value={f.requiredExtensions} onChange={(next) => set('requiredExtensions', next)}
                groups={groupSshExtensions(SSH_EXTENSION_OPTIONS, extensionHelp, (ext) => (conflicts.includes(ext) ? 'warn' : undefined))}
                hint={SSH_REQUIRED_EXTENSIONS_HINT}
                problems={conflicts.length > 0 ? [{ tone: 'warn', message: <>Required but not allowed: <span className="font-mono">{conflicts.join(', ')}</span>. Allow them above or unrequire them before saving.</> }] : []} />
        </div>
    );
};

export default SshCertProfileForm;
