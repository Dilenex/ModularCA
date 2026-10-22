import { describe, expect, it } from 'vitest';
import { KRL_DESTINATION, krlHostSetupCommands, krlLastRevocationText, krlVersionText } from '@adminui/pages/sshKrl';

/**
 * The "Revocation list (KRL)" section of an SSH CA key's page. The fields are those
 * AdminSshController.GetCaKeys adds per key (krlVersion, krlRevokedCertificates,
 * krlLastRevokedAt); the commands install the files of deploy/ssh-krl.
 */

const KRL_URL = 'https://ca.example.com/ssh/ca-keys/6f1c2a3b-0000-4000-8000-00000000c0de/krl';
const format = (iso: string) => `at ${iso}`;

describe('what the page says about a key\'s KRL', () => {
    it('shows version 0 as a version, not as nothing', () => {
        expect(krlVersionText({ krlVersion: 0 })).toBe('0');
        expect(krlVersionText({ krlVersion: 17 })).toBe('17');
    });

    it('shows no version when the API did not say', () => {
        expect(krlVersionText({})).toBeNull();
        expect(krlVersionText({ krlVersion: null })).toBeNull();
    });

    it('gives the time of the newest revocation', () => {
        expect(krlLastRevocationText({ krlRevokedCertificates: 2, krlLastRevokedAt: '2026-10-08T09:30:00Z' }, format))
            .toBe('at 2026-10-08T09:30:00Z');
    });

    it('tells nothing revoked apart from revoked with no time recorded', () => {
        expect(krlLastRevocationText({ krlRevokedCertificates: 0, krlLastRevokedAt: null }, format)).toMatch(/^No certificate/);
        expect(krlLastRevocationText({ krlRevokedCertificates: 3, krlLastRevokedAt: null }, format)).toMatch(/^Not recorded/);
        expect(krlLastRevocationText({}, format)).toBeNull();
    });
});

describe('the commands that set a host up', () => {
    const lines = krlHostSetupCommands(KRL_URL).split('\n');
    const at = (fragment: string) => {
        const index = lines.findIndex((l) => l.includes(fragment));
        expect(index, fragment).toBeGreaterThanOrEqual(0);
        return index;
    };

    it('fetch the list before sshd is told about the file', () => {
        // sshd refuses every public-key login while the file RevokedKeys names is missing.
        const firstFetch = at('systemctl start modularca-krl-fetch.service');
        const timer = at('systemctl enable --now modularca-krl-fetch.timer');
        const revokedKeys = at(`RevokedKeys ${KRL_DESTINATION}`);
        const reload = at('sshd -t && systemctl reload');
        expect(at('systemctl daemon-reload')).toBeLessThan(firstFetch);
        expect(firstFetch).toBeLessThan(timer);
        expect(firstFetch).toBeLessThan(revokedKeys);
        expect(revokedKeys).toBeLessThan(reload);
    });

    it('never write sshd_config themselves and check it before the reload', () => {
        expect(lines.filter((l) => !l.startsWith('#') && l.includes('sshd_config'))).toEqual([]);
        expect(lines[at('systemctl reload')]).toMatch(/^sshd -t && /);
    });

    it('install the script where the unit runs it, and the settings where the unit reads them', () => {
        expect(lines).toContain('install -m 0755 modularca-krl-fetch.sh /usr/local/sbin/modularca-krl-fetch');
        expect(lines).toContain('install -m 0644 modularca-krl-fetch.service modularca-krl-fetch.timer /etc/systemd/system/');
        expect(lines).toContain(`printf 'MODULARCA_KRL_URL=%s\\n' '${KRL_URL}' > /etc/default/modularca-krl-fetch`);
    });

    it('quote the URL so that nothing in it is run', () => {
        const hostile = "https://ca.example.com/krl'; rm -rf /; echo '";
        const line = krlHostSetupCommands(hostile).split('\n').find((l) => l.startsWith('printf'))!;
        expect(line).toBe(`printf 'MODULARCA_KRL_URL=%s\\n' 'https://ca.example.com/krl'\\''; rm -rf /; echo '\\''' > /etc/default/modularca-krl-fetch`);
    });
});
