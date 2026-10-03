using System.Text;
using System.Text.RegularExpressions;
using FluentValidation;
using ModularCA.Auth.Models;
using ModularCA.Shared.Models.Management;

namespace ModularCA.API.Validation.Users;

/// <summary>
/// FluentValidation validators for user-identity fields. Every DTO that
/// accepts a <c>Username</c> or <c>Email</c> — create, update, login, password change,
/// password reset — must pass through one of these validators so the format rules apply
/// uniformly. Username is constrained to <c>^[A-Za-z0-9._-]{1,64}$</c>. Email goes through
/// FluentValidation's <c>.EmailAddress()</c>. Strings are normalized to NFC before any
/// regex or comparison so homoglyph attacks cannot create two rows that render identically
/// but compare as distinct.
/// </summary>
public static partial class UserFieldValidators
{
    /// <summary>Max username length — mirrors the DB column bound.</summary>
    public const int MaxUsernameLength = 64;

    /// <summary>Max email length — RFC 5321 addr-spec ceiling.</summary>
    public const int MaxEmailLength = 254;

    [GeneratedRegex(@"^[A-Za-z0-9._-]{1,64}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex UsernameRegex();

    /// <summary>
    /// Normalizes a user-supplied identity string to Unicode NFC form. Returns <c>null</c>
    /// for null input. Empty input is returned unchanged. This normalization is applied
    /// before regex matching and before any <c>==</c> comparison against a DB row.
    /// </summary>
    public static string? NormalizeIdentity(string? value)
    {
        if (value is null) return null;
        if (value.Length == 0) return value;
        return value.Normalize(NormalizationForm.FormC);
    }

    /// <summary>
    /// Applies the <c>Username</c> validation rule chain to a FluentValidation rule builder.
    /// Centralizes the rule so create / update / login / password-change DTOs all validate
    /// identically.
    /// </summary>
    public static IRuleBuilderOptions<T, string> ValidUsername<T>(this IRuleBuilder<T, string> rule)
    {
        return rule
            .NotEmpty().WithMessage("Username is required.")
            .MaximumLength(MaxUsernameLength)
                .WithMessage($"Username must not exceed {MaxUsernameLength} characters.")
            .Must(u => u != null && UsernameRegex().IsMatch(NormalizeIdentity(u) ?? u))
                .WithMessage("Username may only contain letters, digits, '.', '_' and '-'.");
    }

    /// <summary>
    /// Applies the <c>Username</c> validation rule chain for a nullable username (update DTOs).
    /// Null (unchanged) passes; anything else, the empty string included, must pass the same rules
    /// as <see cref="ValidUsername{T}"/>.
    /// </summary>
    public static IRuleBuilderOptions<T, string?> ValidOptionalUsername<T>(this IRuleBuilder<T, string?> rule)
    {
        return rule
            .MaximumLength(MaxUsernameLength)
                .WithMessage($"Username must not exceed {MaxUsernameLength} characters.")
            .Must(u => u == null || UsernameRegex().IsMatch(NormalizeIdentity(u) ?? u))
                .WithMessage("Username may only contain letters, digits, '.', '_' and '-', and cannot be empty.");
    }

    /// <summary>
    /// Applies the <c>Email</c> validation rule chain.
    /// </summary>
    public static IRuleBuilderOptions<T, string> ValidEmail<T>(this IRuleBuilder<T, string> rule)
    {
        return rule
            .NotEmpty().WithMessage("Email is required.")
            .MaximumLength(MaxEmailLength)
                .WithMessage($"Email must not exceed {MaxEmailLength} characters.")
            .EmailAddress().WithMessage("Email is not in a valid format.");
    }

    /// <summary>
    /// Applies the <c>Email</c> validation rule chain for a nullable email (update DTOs). Null
    /// (unchanged) passes; the empty string does not.
    /// </summary>
    public static IRuleBuilderOptions<T, string?> ValidOptionalEmail<T>(this IRuleBuilder<T, string?> rule)
    {
        return rule
            .MaximumLength(MaxEmailLength)
                .WithMessage($"Email must not exceed {MaxEmailLength} characters.")
            .Must(e => e == null || IsLikelyValidEmail(e))
                .WithMessage("Email is not in a valid format.");
    }

    private static bool IsLikelyValidEmail(string value)
    {
        // Quick sanity check — full RFC 5322 validation is unrealistic. FluentValidation's
        // .EmailAddress() accepts a broad set; for the optional path we replicate a simple
        // structural check.
        if (string.IsNullOrEmpty(value)) return false;
        var at = value.IndexOf('@');
        if (at <= 0 || at >= value.Length - 1) return false;
        if (value.IndexOf('@', at + 1) >= 0) return false;
        return value.Length <= MaxEmailLength;
    }
}

/// <summary>
/// Validator for <see cref="CreateUserRequest"/>. Enforces username / email format rules.
/// </summary>
public class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
{
    public CreateUserRequestValidator()
    {
        RuleFor(x => x.Username).ValidUsername();
        RuleFor(x => x.Email).ValidEmail();
        RuleFor(x => x.FirstName).MaximumLength(100);
        RuleFor(x => x.LastName).MaximumLength(100);
    }
}

/// <summary>
/// Validator for <see cref="UpdateUserRequest"/>. Username and email are optional but when
/// supplied must match the same rules as create.
/// </summary>
public class UpdateUserRequestValidator : AbstractValidator<UpdateUserRequest>
{
    public UpdateUserRequestValidator()
    {
        RuleFor(x => x.Username).ValidOptionalUsername();
        RuleFor(x => x.Email).ValidOptionalEmail();
        RuleFor(x => x.FirstName).MaximumLength(100);
        RuleFor(x => x.LastName).MaximumLength(100);
    }
}

/// <summary>
/// Validator for <see cref="LoginRequest"/>. Username format is validated even on the login
/// path so unicode-homoglyph / overlong-input probes are rejected before reaching the auth
/// service.
/// </summary>
public class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Username).ValidUsername();
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required.")
            .MaximumLength(1024)
                .WithMessage("Password must not exceed 1024 characters.");
    }
}

/// <summary>
/// Validator for <see cref="PreJwtChangePasswordRequest"/>. Applies the username rule plus
/// generous length caps on the password fields; the underlying password policy runs
/// server-side.
/// </summary>
public class PreJwtChangePasswordRequestValidator : AbstractValidator<PreJwtChangePasswordRequest>
{
    public PreJwtChangePasswordRequestValidator()
    {
        RuleFor(x => x.Username).ValidUsername();
        RuleFor(x => x.OldPassword)
            .NotEmpty().MaximumLength(1024);
        RuleFor(x => x.NewPassword)
            .NotEmpty().MaximumLength(1024);
        RuleFor(x => x.ConfirmNewPassword)
            .NotEmpty().MaximumLength(1024);
    }
}
