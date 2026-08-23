using System.Text.RegularExpressions;

namespace ModularCA.Shared.Utils
{
    /// <summary>
    /// Parses ISO 8601 duration strings into <see cref="TimeSpan"/> values.
    /// <para>
    /// This is the single source of truth for <c>ValidityPeriodMax</c> on every issuance path —
    /// ACME, EST, SCEP, CMP, cert-manager, public enrollment and admin issuance all reach it
    /// through <c>IssuanceValidationService</c> — so a misparse here is a silent failure of the
    /// maximum-validity control.
    /// </para>
    /// <para>
    /// The previous implementation was <c>Regex.Matches(duration, @"(\d+)([YMD])")</c> over the
    /// string with its leading <c>P</c> removed, which had three distinct failure modes:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// The <c>T</c> separator was never handled, so the <c>M</c> in <c>PT30M</c> — thirty
    /// MINUTES, the obvious choice for short-lived certificates — was read as thirty MONTHS. A
    /// profile asking for a half-hour ceiling silently got two and a half years: a fail-open on
    /// the control's whole purpose.
    /// </item>
    /// <item>
    /// Forms it did not understand matched nothing and returned <see cref="TimeSpan.Zero"/>
    /// rather than failing. <c>P1W</c> and <c>PT12H</c> both yielded a ceiling of "now", so every
    /// request under that profile was rejected with no indication why.
    /// </item>
    /// <item>
    /// <c>int.Parse</c> and <c>AddYears</c> were unguarded, so <c>P99999999999D</c> threw
    /// <see cref="OverflowException"/> and <c>P9999Y</c> threw
    /// <see cref="ArgumentOutOfRangeException"/> straight out of the issuance path.
    /// </item>
    /// </list>
    /// <para>
    /// It now parses the full grammar, and anything it cannot represent throws
    /// <see cref="FormatException"/> instead of quietly returning a wrong duration. For a
    /// security ceiling, refusing to answer beats answering incorrectly.
    /// </para>
    /// </summary>
    public class Iso8601ParserUtil()
    {
        // PnYnMnWnD followed by an optional TnHnMnS. Anchored, so trailing junk is rejected
        // rather than ignored. Fractional components (PT0.5H) are deliberately unsupported and
        // rejected rather than truncated.
        private static readonly Regex DurationPattern = new(
            @"^P(?!$)(?:(?<y>\d+)Y)?(?:(?<mo>\d+)M)?(?:(?<w>\d+)W)?(?:(?<d>\d+)D)?"
            + @"(?:T(?!$)(?:(?<h>\d+)H)?(?:(?<mi>\d+)M)?(?:(?<s>\d+)S)?)?$",
            // Named groups throughout: ExplicitCapture (used here originally) makes UNNAMED
            // groups non-capturing, so numbered lookups silently returned nothing.
            RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
            TimeSpan.FromMilliseconds(100));

        // Guards AddYears/AddMonths/AddDays, which throw once the result leaves DateTime's range.
        private const int MaxYears = 1000;
        private const int MaxMonths = 12_000;
        private const int MaxWeeks = 52_000;
        private const int MaxDays = 365_000;

        /// <summary>
        /// Converts an ISO 8601 duration into a <see cref="TimeSpan"/>.
        /// <para>
        /// Calendar components (years, months) are resolved against the current UTC instant,
        /// because their length depends on where they land — a year is 365 or 366 days.
        /// </para>
        /// </summary>
        /// <exception cref="FormatException">
        /// Thrown when the duration is malformed, uses a component this parser cannot represent,
        /// or specifies a magnitude outside the supported range. Callers treat this as a
        /// configuration error; it must never be silently coerced to zero.
        /// </exception>
        public static TimeSpan ParseIso8601(string duration)
        {
            if (string.IsNullOrWhiteSpace(duration))
                throw new FormatException("Duration is empty.");

            Match match;
            try
            {
                match = DurationPattern.Match(duration.Trim());
            }
            catch (RegexMatchTimeoutException)
            {
                throw new FormatException($"Duration '{duration}' could not be parsed in time.");
            }

            if (!match.Success)
            {
                throw new FormatException(
                    $"'{duration}' is not a supported ISO 8601 duration. Expected forms like "
                    + "P1Y, P6M, P30D, PT12H, PT30M, or a combination such as P1Y6M10D. "
                    + "Fractional values are not supported.");
            }

            int Part(string group, int max, string name)
            {
                if (!match.Groups[group].Success) return 0;
                if (!int.TryParse(match.Groups[group].Value, out var value) || value > max)
                    throw new FormatException($"Duration component {name} in '{duration}' is out of range (max {max}).");
                return value;
            }

            var years = Part("y", MaxYears, "years");
            var months = Part("mo", MaxMonths, "months");
            var weeks = Part("w", MaxWeeks, "weeks");
            var days = Part("d", MaxDays, "days");
            var hours = Part("h", 100_000, "hours");
            var minutes = Part("mi", 10_000_000, "minutes");
            var seconds = Part("s", 100_000_000, "seconds");

            // An explicit zero (P0D) is legitimate and must NOT throw: IssuanceValidationService
            // passes "P0D" as the default ValidityPeriodMin, meaning "no minimum". A bare "P" or
            // "PT" is already rejected by the (?!$) guards in the pattern.

            try
            {
                var now = DateTime.UtcNow;
                var future = now
                    .AddYears(years)
                    .AddMonths(months)
                    .AddDays(weeks * 7 + days)
                    .AddHours(hours)
                    .AddMinutes(minutes)
                    .AddSeconds(seconds);
                return future - now;
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new FormatException($"Duration '{duration}' is too large to represent.", ex);
            }
        }
    }
}
