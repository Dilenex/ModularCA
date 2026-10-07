import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { CARD_FIELDS, type SettingDescription, describeField, fieldBadges, fieldLocked, fieldsApply, indexSettings, secretState } from '@adminui/pages/settingsMeta';

const setting = (path: string, over: Partial<SettingDescription> = {}): SettingDescription => ({
    key: path.replace(/\./g, '_'), path, section: path.split('.')[0],
    kept: 'database', applies: 'live', source: 'default', secret: false,
    version: null, updatedBy: null, updatedAt: null, ...over,
});

const index = indexSettings([
    setting('Acme.EnforceCaa'),
    setting('Acme.Http01.MaxAddresses', { source: 'database', version: 2 }),
    setting('IpWhitelist.Enabled', { applies: 'restart' }),
    setting('IpWhitelist.ExemptPaths'),
    setting('Http.Port', { kept: 'host', applies: 'restart', source: 'file' }),
    setting('Http.CorsOrigins', { applies: 'restart' }),
    setting('Email.Password', { secret: true, source: 'environment' }),
    setting('DB.App.Host', { kept: 'bootstrap', applies: 'restart', source: 'file' }),
]);

describe('what the settings page says beside a field', () => {
    it('finds a setting by the name the page gives the field, whatever its case', () => {
        expect(describeField(index, 'acme.enforceCaa')?.key).toBe('Acme_EnforceCaa');
        expect(describeField(index, 'metrics.enabled')).toBeUndefined();
        expect(describeField(index, undefined)).toBeUndefined();
    });

    it('says a database setting is live or waits for a restart', () => {
        expect(fieldBadges(describeField(index, 'acme.enforceCaa')).map((b) => b.label)).toEqual(['Live']);
        expect(fieldBadges(describeField(index, 'ipWhitelist.enabled')).map((b) => b.label)).toEqual(['Restart']);
    });

    it('says a host setting is this host\'s as well', () => {
        expect(fieldBadges(describeField(index, 'http.port')).map((b) => b.label)).toEqual(['This host', 'Restart']);
        expect(fieldBadges(describeField(index, 'db.app.host')).map((b) => b.label)).toEqual(['File', 'Restart']);
    });

    it('says only that the environment decides, where it does, and locks the field', () => {
        const password = describeField(index, 'email.password');
        expect(fieldBadges(password).map((b) => b.label)).toEqual(['Environment']);
        expect(fieldLocked(password)).toBe(true);
        expect(fieldLocked(describeField(index, 'acme.enforceCaa'))).toBe(false);
    });

    it('says nothing about a field the server does not describe', () => {
        expect(fieldBadges(undefined)).toEqual([]);
        expect(fieldLocked(undefined)).toBe(false);
    });
});

describe('what a card says about its settings', () => {
    it('is live when every one is, restart when every one waits, and says so when they differ', () => {
        expect(fieldsApply(index, ['acme.enforceCaa', 'acme.http01.maxAddresses'])).toBe('live');
        expect(fieldsApply(index, ['http.port', 'http.corsOrigins'])).toBe('restart');
        expect(fieldsApply(index, ['ipWhitelist.enabled', 'ipWhitelist.exemptPaths'])).toBe('mixed');
    });

    it('speaks only of the settings it is given, not of the rest of their section', () => {
        expect(fieldsApply(index, ['ipWhitelist.exemptPaths'])).toBe('live');
        expect(fieldsApply(index, ['ipWhitelist.enabled'])).toBe('restart');
    });

    it('has nothing to say where the server describes none of them', () => {
        expect(fieldsApply(index, ['metrics.enabled'])).toBeNull();
        expect(fieldsApply(index, [])).toBeNull();
        expect(fieldsApply(index, undefined)).toBeNull();
        // One it does not describe does not change what the others say.
        expect(fieldsApply(index, ['metrics.enabled', 'acme.enforceCaa'])).toBe('live');
    });
});

describe('what the page says of a secret it never sees', () => {
    const stored = setting('JWT.Secret', { secret: true, applies: 'restart', source: 'database', version: 3 });

    it('is stored once the database holds it, and in the file until then', () => {
        expect(secretState(stored, [])).toBe('stored');
        expect(secretState(setting('JWT.Secret', { secret: true, source: 'file' }), [])).toBe('file');
    });

    it('waits for a restart when a new one was stored since this node started', () => {
        expect(secretState(stored, ['JWT_Secret'])).toBe('waiting');
        expect(secretState(stored, ['Email_Password'])).toBe('stored');
        expect(secretState(stored, undefined)).toBe('stored');
    });

    it('is the environment\'s where a variable supplies it, whatever is stored', () => {
        expect(secretState(setting('JWT.Secret', { secret: true, source: 'environment', version: 3 }), ['JWT_Secret'])).toBe('environment');
    });

    it('says nothing of one the server does not describe', () => {
        expect(secretState(undefined, ['JWT_Secret'])).toBeNull();
    });
});

/*
 * A card's header says when a change takes effect from CARD_FIELDS, and each field says it from
 * its own `path`. The two agree only while the list is the fields the card shows, which is what
 * this reads the page's source to check.
 */
describe('the fields each card of the Settings page is said to hold', () => {
    const source = readFileSync(resolve(__dirname, '../../../../modularca.adminui/src/pages/Settings.tsx'), 'utf8');
    const header = /<SectionHeader (?:fields=\{CARD_FIELDS\.(\w+)\} )?title="[^"]*" expanded=\{expanded === '(\w+)'\}/g;
    const cards = [...source.matchAll(header)].map((m, i, all) => {
        const body = source.slice(m.index! + m[0].length, i + 1 < all.length ? all[i + 1].index : source.length);
        return { named: m[1], key: m[2], paths: [...new Set([...body.matchAll(/\bpath="([A-Za-z0-9.]+)"/g)].map((p) => p[1]))] };
    });

    it('finds the cards', () => {
        expect(cards.length).toBeGreaterThan(30);
        expect(source.match(/<SectionHeader /g)?.length).toBe(cards.length);
    });

    it('are the fields the card shows', () => {
        for (const card of cards) {
            expect([...(CARD_FIELDS[card.key] ?? [])].sort(), card.key).toEqual([...card.paths].sort());
            expect(card.named, card.key).toBe(card.paths.length ? card.key : undefined);
        }
        expect(Object.keys(CARD_FIELDS).sort()).toEqual(cards.filter((c) => c.paths.length).map((c) => c.key).sort());
    });
});
