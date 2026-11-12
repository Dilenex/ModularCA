import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';

/**
 * The claim page's logic, apart from its form: what it checks before sending, what it sends, and
 * what it does with the answer. Kept free of React and of `portal.ts` (which reads the address bar
 * at load) so it can be tested on its own.
 */

/** Router state the claim page hands the sign-in page after a claim, to prefill the username. */
export interface ClaimedState {
    claimed: { username: string };
}

/** What the claim form holds when it is submitted. */
export interface ClaimForm {
    token: string;
    newPassword: string;
    confirmNewPassword: string;
}

/** The call that redeems a claim token, `apiClaimAccount` in the page. */
export type ClaimCall = (token: string, newPassword: string, confirmNewPassword: string) => Promise<{ username: string }>;

/** Where the page goes after a claim, or the error it shows. */
export type ClaimOutcome =
    | { ok: true; to: string; state: ClaimedState }
    | { ok: false; error: NoticeInput | null };

export const CLAIM_TOKEN_REQUIRED = 'Enter the claim token you were given';
export const CLAIM_PASSWORD_MISMATCH = 'New password and confirmation do not match';

/**
 * What stops the form being sent, or `null` when it can be. A token of nothing but spaces passes
 * the field's `required` check and is caught here, before it spends one of the endpoint's
 * rate-limited attempts.
 */
export function validateClaim(form: ClaimForm): string | null {
    if (!form.token.trim()) return CLAIM_TOKEN_REQUIRED;
    if (form.newPassword !== form.confirmNewPassword) return CLAIM_PASSWORD_MISMATCH;
    return null;
}

/**
 * Checks the form, redeems the token (trimmed, since it is pasted) and says what follows: on
 * success the sign-in page at `loginPath` with the claimed username as router state, otherwise
 * the error to show. A refusal keeps the server's sentence, which is the same for every refused
 * token and lists the policy's objections for a password it turns down.
 */
export async function submitClaim(form: ClaimForm, claim: ClaimCall, loginPath: string): Promise<ClaimOutcome> {
    const invalid = validateClaim(form);
    if (invalid) return { ok: false, error: invalid };
    try {
        const result = await claim(form.token.trim(), form.newPassword, form.confirmNewPassword);
        return { ok: true, to: loginPath, state: { claimed: { username: result.username } } };
    } catch (err) {
        return { ok: false, error: errorNotice(err, 'Unexpected error') };
    }
}
