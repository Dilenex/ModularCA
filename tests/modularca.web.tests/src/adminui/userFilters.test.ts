import { describe, expect, it } from 'vitest';
import { userMatches, userStatus, type UserFilter } from '@adminui/pages/userFilters';

const any: UserFilter = { search: '', status: '', signIn: '', groupId: '' };
const now = new Date('2026-10-06T12:00:00Z');
const alice = { username: 'alice', email: 'alice@example.test', isActive: true, lastLoginAt: '2026-10-05T09:00:00Z', groups: [{ groupId: 'g1' }] };
const bob = { username: 'bob', email: 'bob@example.test', isActive: true, lastLoginAt: null, groups: [] };
const carol = { username: 'carol', email: 'c@example.test', isActive: false, lastLoginAt: '2026-05-01T09:00:00Z', groups: [{ groupId: 'g2' }] };
const dave = { username: 'dave', email: 'd@example.test', isActive: false, isLocked: true, lastLoginAt: '2026-09-30T09:00:00Z' };

describe('users table filters', () => {
    it('shows everyone with no filter', () => {
        for (const u of [alice, bob, carol, dave]) expect(userMatches(u, any, now)).toBe(true);
    });

    it('searches username and email', () => {
        expect(userMatches(alice, { ...any, search: 'ALI' }, now)).toBe(true);
        expect(userMatches(carol, { ...any, search: 'c@example' }, now)).toBe(true);
        expect(userMatches(bob, { ...any, search: 'ali' }, now)).toBe(false);
    });

    it('reads a locked account as locked even when it is also disabled', () => {
        expect(userStatus(dave)).toBe('locked');
        expect(userMatches(dave, { ...any, status: 'locked' }, now)).toBe(true);
        expect(userMatches(dave, { ...any, status: 'disabled' }, now)).toBe(false);
        expect(userMatches(carol, { ...any, status: 'disabled' }, now)).toBe(true);
        expect(userMatches(alice, { ...any, status: 'active' }, now)).toBe(true);
    });

    it('finds accounts that never signed in', () => {
        expect(userMatches(bob, { ...any, signIn: 'never' }, now)).toBe(true);
        expect(userMatches(alice, { ...any, signIn: 'never' }, now)).toBe(false);
    });

    it('counts never-signed-in accounts as stale too', () => {
        expect(userMatches(bob, { ...any, signIn: '90' }, now)).toBe(true);
        expect(userMatches(carol, { ...any, signIn: '90' }, now)).toBe(true);
        expect(userMatches(alice, { ...any, signIn: '90' }, now)).toBe(false);
    });

    it('narrows to members of one group', () => {
        expect(userMatches(alice, { ...any, groupId: 'g1' }, now)).toBe(true);
        expect(userMatches(carol, { ...any, groupId: 'g1' }, now)).toBe(false);
        expect(userMatches(dave, { ...any, groupId: 'g1' }, now)).toBe(false);
    });
});
