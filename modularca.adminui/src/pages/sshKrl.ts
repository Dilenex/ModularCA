/**
 * Pure helpers behind the "Revocation list (KRL)" section of an SSH CA key's page: what the key
 * list says about the key's KRL, and the commands that set a server up to fetch it.
 *
 * The files the commands install are shipped with the CA, in KRL_FETCHER_DIRECTORY on the CA
 * host (deploy/ssh-krl in the source tree). The script's own header is the reference for its
 * options; this page only gives the order that keeps sshd reachable.
 */

/** What `GET /api/v1/admin/ssh/ca-keys` says about one SSH CA key's KRL. */
export interface SshCaKeyKrlFields {
    krlUrl?: string | null;
    krlVersion?: number | null;
    krlRevokedCertificates?: number | null;
    krlLastRevokedAt?: string | null;
}

/** Where the fetcher's files are on a host the CA is installed on. */
export const KRL_FETCHER_DIRECTORY = '/usr/share/modularca/ssh-krl';

/** The file the fetcher installs by default, and sshd's RevokedKeys names. */
export const KRL_DESTINATION = '/etc/ssh/revoked_keys.krl';

/** The KRL's version as the page shows it; null when the API did not say. */
export function krlVersionText(key: SshCaKeyKrlFields): string | null {
    return typeof key.krlVersion === 'number' ? String(key.krlVersion) : null;
}

/**
 * When a certificate of the key was last revoked, as the page shows it. A certificate revoked
 * before the CA recorded the time counts in the version and has no time to show.
 */
export function krlLastRevocationText(key: SshCaKeyKrlFields, formatDate: (iso: string) => string): string | null {
    if (typeof key.krlRevokedCertificates !== 'number') return null;
    if (key.krlLastRevokedAt) return formatDate(key.krlLastRevokedAt);
    return key.krlRevokedCertificates === 0
        ? 'No certificate of this key has been revoked.'
        : 'Not recorded. The certificates in this list were revoked before the time was kept.';
}

/** A value inside single quotes for a POSIX shell. */
function shellQuote(value: string): string {
    return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * The commands that set one server up to fetch the key's KRL every minute, to run on the server
 * as root from the directory the fetcher's files were copied to. The order matters: the first
 * fetch comes before sshd is told about the file, because sshd refuses every public-key login
 * while the file RevokedKeys names is missing.
 */
export function krlHostSetupCommands(krlUrl: string): string {
    return [
        'install -m 0755 modularca-krl-fetch.sh /usr/local/sbin/modularca-krl-fetch',
        'install -m 0644 modularca-krl-fetch.service modularca-krl-fetch.timer /etc/systemd/system/',
        `printf 'MODULARCA_KRL_URL=%s\\n' ${shellQuote(krlUrl)} > /etc/default/modularca-krl-fetch`,
        'systemctl daemon-reload',
        '',
        '# The first fetch. It must succeed before sshd is told about the file.',
        'systemctl start modularca-krl-fetch.service',
        `ssh-keygen -Q -l -f ${KRL_DESTINATION}`,
        'systemctl enable --now modularca-krl-fetch.timer',
        '',
        '# Only now, add this line to /etc/ssh/sshd_config:',
        `#   RevokedKeys ${KRL_DESTINATION}`,
        '# then check the configuration and reload sshd (the unit is named sshd on some distributions).',
        'sshd -t && systemctl reload ssh',
    ].join('\n');
}
