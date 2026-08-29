/**
 * QR Code SVG generator backed by the qrcode-generator library.
 *
 * SECURITY — the SVG produced by this generator is
 * consumed via `dangerouslySetInnerHTML` in MfaSetup.tsx, MySecurity.tsx, and
 * EnrollmentManagement.tsx. The encoded text (e.g. an otpauth:// URI from the
 * backend) is rendered as a bitmap of `<rect>` elements with NUMERIC
 * coordinates only — no `<text>`, no `<title>`, no string interpolation into
 * any attribute. **DO NOT** modify this generator to:
 *   - emit `<text>` / `<title>` / `<desc>` elements containing the input
 *   - interpolate the input string into any SVG attribute or comment
 *   - accept HTML/SVG fragments from callers
 * Doing so turns the existing `dangerouslySetInnerHTML` consumers into XSS
 * sinks because the backend builds provisioning URIs from user-controlled
 * fields (username, configured issuer). If you need to display label text,
 * render it as a sibling React element outside the SVG — never inside it.
 *
 * SHARED. adminui and userui had unrelated implementations: this one, backed by the
 * `qrcode-generator` package, and a 308-line hand-rolled encoder in userui carrying its own
 * Reed-Solomon arithmetic. The hand-rolled one had none of the review below and was generating
 * the TOTP provisioning code users scan to enrol a second factor. The library version wins.
 * It lives in shared/authenticated rather than shared/common for a mechanical reason: it is
 * the only shared file with a third-party dependency, and all three anonymous SPAs list
 * ../shared/common/src in their tsconfig include, so every file there is typechecked by apps
 * that have no such package installed. shared/authenticated is included only by the two SPAs
 * that actually render a QR code, which is the same set that needs the dependency.
 *
 */

import qrcode from 'qrcode-generator';

/**
 * Generates a QR code as an SVG string for the given text.
 * Uses error correction level L for maximum data capacity.
 */
export function generateQrSvg(text: string, moduleSize: number = 4, margin: number = 4): string {
  // Type 0 = auto-detect version
  const qr = qrcode(0, 'L');
  qr.addData(text);
  qr.make();

  const count = qr.getModuleCount();
  const totalSize = (count + margin * 2) * moduleSize;

  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalSize} ${totalSize}" width="${totalSize}" height="${totalSize}">`;
  svg += `<rect width="${totalSize}" height="${totalSize}" fill="white"/>`;

  for (let r = 0; r < count; r++) {
    for (let c = 0; c < count; c++) {
      if (qr.isDark(r, c)) {
        svg += `<rect x="${(c + margin) * moduleSize}" y="${(r + margin) * moduleSize}" width="${moduleSize}" height="${moduleSize}" fill="black"/>`;
      }
    }
  }

  svg += '</svg>';
  return svg;
}
