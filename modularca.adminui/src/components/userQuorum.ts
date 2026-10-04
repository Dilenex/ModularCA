/**
 * Validation for the controlled-user quorum inputs. Free of React so the web tests cover it.
 */

/** What a quorum value is checked against. */
export interface QuorumRules {
    /** Whether blank (inherit the parent's value) is allowed. */
    allowInherit: boolean;
    /** The ceiling: a CA may require fewer approvals than its parent scope, never more. */
    max?: number | null;
    /** Names the ceiling in the message, e.g. "the instance's quorum". */
    maxLabel?: string;
}

/** Why `value` cannot be saved, or `null` when it can. */
export function quorumProblem(value: string, rules: QuorumRules): string | null {
    const v = value.trim();
    if (v === '') return rules.allowInherit ? null : 'Enter a quorum.';
    if (!/^\d+$/.test(v)) return 'Enter a whole number.';
    const n = parseInt(v, 10);
    if (n < 1) return 'The quorum is at least 1 approver other than the initiator.';
    if (rules.max != null && n > rules.max) return `Can't exceed ${rules.maxLabel ?? 'the parent quorum'} (${rules.max}).`;
    return null;
}
