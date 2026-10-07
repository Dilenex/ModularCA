/*
 * The Users table's filters. The list holds every user, so they are applied here. No React, so
 * tests/modularca.web.tests can cover them.
 */

export interface UserRow {
    username?: string;
    email?: string;
    isActive?: boolean;
    isLocked?: boolean;
    lastLoginAt?: string | null;
    groups?: { groupId: string }[] | null;
}

export interface UserFilter {
    search: string;
    /** '' for any, else 'active', 'locked' or 'disabled'. */
    status: string;
    /** '' for any, 'never', or a number of days since the last sign-in. */
    signIn: string;
    /** '' for any, else a group the user must belong to. */
    groupId: string;
}

/** A user's state as the Status column shows it: locked wins over disabled. */
export const userStatus = (u: UserRow): 'active' | 'locked' | 'disabled' =>
    u.isLocked ? 'locked' : u.isActive === false ? 'disabled' : 'active';

const DAY_MS = 24 * 60 * 60 * 1000;

export function userMatches(u: UserRow, f: UserFilter, now: Date = new Date()): boolean {
    if (f.search) {
        const s = f.search.toLowerCase();
        if (!(u.username || '').toLowerCase().includes(s) && !(u.email || '').toLowerCase().includes(s)) return false;
    }
    if (f.status && userStatus(u) !== f.status) return false;
    if (f.signIn === 'never' && u.lastLoginAt) return false;
    if (f.signIn && f.signIn !== 'never') {
        // "Not in the last N days" includes users who never signed in.
        const days = Number(f.signIn);
        if (u.lastLoginAt && now.getTime() - new Date(u.lastLoginAt).getTime() < days * DAY_MS) return false;
    }
    if (f.groupId && !(u.groups || []).some((g) => g.groupId === f.groupId)) return false;
    return true;
}
