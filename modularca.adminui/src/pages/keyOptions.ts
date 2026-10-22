import type { ServerKeyOption, ServerKeyRefusal } from '@shared/generated';

/**
 * The key choice of the certificate request form's "Generate key pair" path. The server says
 * which keys the chosen signing profile and certificate profile accept (`key-options`); this
 * turns that list into the two pickers and keeps the choice inside it. No React here, so it is
 * covered by tests/modularca.web.tests.
 */

export interface KeyChoice {
    algorithm: string;
    /** The RSA size or ECDSA curve; null for an algorithm that has neither. */
    keySize: string | null;
}

type KeyLike = { algorithm: string; keySize?: string | null };

/** The algorithms offered, each once, in the server's order. */
export function offeredAlgorithms(options: readonly ServerKeyOption[]): string[] {
    return [...new Set(options.map((o) => o.algorithm))];
}

/** The sizes or curves offered for an algorithm; empty for one that has none. */
export function offeredSizes(options: readonly ServerKeyOption[], algorithm: string): string[] {
    return options.filter((o) => o.algorithm === algorithm && o.keySize != null).map((o) => o.keySize as string);
}

/** The offered key a choice names, if it is offered. */
export function findOption(options: readonly ServerKeyOption[], choice: KeyChoice | null): ServerKeyOption | undefined {
    if (!choice) return undefined;
    return options.find((o) => o.algorithm === choice.algorithm && (o.keySize ?? null) === choice.keySize);
}

/**
 * The choice to hold once the offered keys are known: the current one while it is offered,
 * else the first size of the same algorithm, else the first key offered. Null when none is.
 */
export function settleKeyChoice(options: readonly ServerKeyOption[], current: KeyChoice | null): KeyChoice | null {
    const kept = findOption(options, current)
        ?? (current ? options.find((o) => o.algorithm === current.algorithm) : undefined)
        ?? options[0];
    return kept ? { algorithm: kept.algorithm, keySize: kept.keySize ?? null } : null;
}

/** The choice after the algorithm picker changes: that algorithm's first offered key. */
export function chooseAlgorithm(options: readonly ServerKeyOption[], algorithm: string): KeyChoice | null {
    const first = options.find((o) => o.algorithm === algorithm);
    return first ? { algorithm, keySize: first.keySize ?? null } : null;
}

/** `keySize` as the request handlers read it: the algorithm's own name where there is no size. */
export function requestKeySize(choice: KeyChoice): string {
    return choice.keySize ?? choice.algorithm;
}

/** "RSA 2048", "ECDSA P-256", "Ed25519". */
export function keyLabel(key: KeyLike): string {
    return key.keySize ? `${key.algorithm} ${key.keySize}` : key.algorithm;
}

/** The refused keys under the reason each was refused for, reasons in first-seen order. */
export function groupRefusals(refused: readonly ServerKeyRefusal[]): { reason: string; keys: string[] }[] {
    const groups = new Map<string, string[]>();
    for (const r of refused) {
        const keys = groups.get(r.reason) ?? [];
        keys.push(keyLabel(r));
        groups.set(r.reason, keys);
    }
    return [...groups].map(([reason, keys]) => ({ reason, keys }));
}
