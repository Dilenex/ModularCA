/**
 * Shared pieces for the profile form tests.
 *
 * `dtoKeys<T>()` takes an object literal with exactly one `true` per property of `T`. It fails to
 * typecheck when the literal misses a property of `T` or names one `T` does not have, so the list
 * a test compares a request body against is tied to the generated request type by `tsc -b`, not
 * by whoever last edited the test.
 */
export function dtoKeys<T>(keys: { [K in keyof Required<T>]: true }): string[] {
    return Object.keys(keys).sort();
}

/** The sorted keys a request body actually carries, including those whose value is null. */
export const bodyKeys = (body: object): string[] => Object.keys(body).sort();

/** Parses a JSON-array string field from a request body. */
export const jsonList = (value: unknown): unknown[] => JSON.parse(String(value));

/** Splits the comma-separated usage lists the cert profile body sends. */
export const csv = (value: unknown): string[] => String(value).split(',').map((s) => s.trim()).filter(Boolean);
