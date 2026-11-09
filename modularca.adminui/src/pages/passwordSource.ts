import { PasswordSource } from '@shared/generated';

/**
 * The pure half of the password source controls on the user page and the ceremony drawer: what
 * each source means, and how to read one from stored ceremony parameters. No React here, so the
 * web tests cover it.
 */

/** Every password source, in the order the select lists them. */
export const PASSWORD_SOURCES: readonly PasswordSource[] = [PasswordSource.Inherit, PasswordSource.Local, PasswordSource.Directory];

/** What each password source means: a short label and the help text under the select. */
export const PASSWORD_SOURCE_TEXT: Readonly<Record<PasswordSource, { label: string; hint: string }>> = {
    Inherit: {
        label: 'Inherit',
        hint: 'Follows the instance LDAP setting. With LDAP on, the directory is asked first; the first password it accepts makes this account Directory.',
    },
    Local: {
        label: 'Local',
        hint: 'Checked against the password stored here only. The directory is never asked, so sign-in works during an LDAP outage. Use for break-glass accounts.',
    },
    Directory: {
        label: 'Directory',
        hint: 'Checked by LDAP only. The password stored here is never used; if the directory cannot be reached or no longer has the account, password sign-in is refused.',
    },
};

/**
 * The source an account record carries, defaulting to Inherit for a record from a server that
 * predates the field.
 */
export function accountPasswordSource(user: { passwordSource?: PasswordSource | null } | null | undefined): PasswordSource {
    const v = user?.passwordSource;
    return v && PASSWORD_SOURCES.includes(v) ? v : PasswordSource.Inherit;
}

/**
 * The name of a password source as stored in a ceremony's parameters, which hold the enum as its
 * number (0 Inherit, 1 Local, 2 Directory). A name is returned as is; anything else as text.
 */
export function storedPasswordSourceName(v: unknown): string {
    if (typeof v === 'number') return PASSWORD_SOURCES[v] ?? String(v);
    return String(v);
}
