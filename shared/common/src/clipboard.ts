/**
 * Copying a short string to the clipboard, on every origin the SPAs are served from.
 *
 * `navigator.clipboard` is [SecureContext]-gated, so it is UNDEFINED on a plain http:// origin —
 * exactly the deployment `publicui` exists to serve, since `HttpSchemeEnforcementMiddleware`
 * allow-lists the public portal for relying parties that do not have TLS trust yet. The same
 * gating already broke `crypto.randomUUID` in that app's toast provider. A copy button that
 * throws a TypeError on the one origin where the operator most needs to quote an error code is
 * worse than no button, so this falls back to the deprecated `execCommand` path rather than
 * assuming the modern API is there.
 *
 * Returns whether the text was copied, so a caller can show "Copied" only when it actually was.
 */
export async function copyText(text: string): Promise<boolean> {
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(text);
            return true;
        }
    } catch {
        // Permission denied, or a non-secure context that exposes the object but not the grant.
        // Fall through to the legacy path rather than reporting failure straight away.
    }

    try {
        // The legacy path has to select the text, which moves focus. Put it back afterwards: the
        // operator may have been mid-word in a form field when they reached for the copy button.
        const previouslyFocused = document.activeElement as HTMLElement | null;
        const scratch = document.createElement('textarea');
        scratch.value = text;
        // Off-screen rather than display:none — a hidden element cannot be selected.
        scratch.setAttribute('readonly', '');
        scratch.style.position = 'fixed';
        scratch.style.top = '-1000px';
        scratch.style.opacity = '0';
        document.body.appendChild(scratch);
        scratch.select();
        const copied = document.execCommand('copy');
        document.body.removeChild(scratch);
        previouslyFocused?.focus?.();
        return copied;
    } catch {
        return false;
    }
}
