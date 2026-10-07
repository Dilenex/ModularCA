/** The most targets the server lets one step-up verification cover (MfaStepUpController.MaxStepUpTargets). */
export const STEP_UP_BATCH = 100;

export const STEP_UP_CANCELLED = 'Step-up MFA cancelled';

export interface StepUpBatchResult {
    ok: number;
    /** One message per item that failed. */
    failures: string[];
    /** The user dismissed a prompt; the items from that prompt on were not attempted. */
    cancelled: boolean;
}

/** The header a call carries when the caller already holds the token. */
export const mfaHeader = (token: string): Record<string, string> => ({ 'X-MFA-Token': token });

/**
 * Runs one gated call per item with one step-up prompt for the lot, not one per item. The
 * prompt names every item's id, and the token it returns is good once for each. More than
 * {@link STEP_UP_BATCH} items are prompted for in groups. One item failing does not stop the rest.
 */
export async function runWithOneStepUp<T>(
    items: T[],
    idOf: (item: T) => string,
    requireStepUp: (operation: string, targetId?: string | string[]) => Promise<string>,
    operation: string,
    call: (item: T, headers: Record<string, string>) => Promise<unknown>,
): Promise<StepUpBatchResult> {
    const result: StepUpBatchResult = { ok: 0, failures: [], cancelled: false };
    for (let start = 0; start < items.length; start += STEP_UP_BATCH) {
        const group = items.slice(start, start + STEP_UP_BATCH);
        let token: string;
        try {
            token = await requireStepUp(operation, group.map(idOf));
        } catch (err: any) {
            if (err?.message !== STEP_UP_CANCELLED) throw err;
            result.cancelled = true;
            return result;
        }
        const headers = mfaHeader(token);
        for (const item of group) {
            try {
                await call(item, headers);
                result.ok++;
            } catch (err: any) {
                result.failures.push(err?.message || 'Failed');
            }
        }
    }
    return result;
}
