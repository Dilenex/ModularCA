using ModularCA.Auth.Services;

namespace ModularCA.Auth.Utils;

/// <summary>
/// Single-use claims for second-factor proofs, made through <see cref="IReplayGuard"/> so that of
/// any number of concurrent verifications presenting the same proof, on one node or across nodes
/// sharing Redis, exactly one is accepted. A verification that checks the proof, then records it
/// in the database or removes it from the cache, lets two concurrent requests both pass the check;
/// the claim is the step that decides.
/// </summary>
/// <remarks>
/// Claims are made only after the proof itself has verified, so a caller presenting made-up codes
/// or assertions cannot fill the guard, and a failed attempt does not burn a challenge the user
/// may still answer.
/// </remarks>
public static class MfaSingleUse
{
    /// <summary>
    /// How long a TOTP time step's claim is remembered. A code for step <c>S</c> is accepted while
    /// the current step is within the verification window around <c>S</c> (at most one step either
    /// side), so at most 90 seconds after it is first usable; four minutes covers that with room
    /// for clock skew between nodes. After that the database's <c>LastUsedTimeStep</c> refuses it.
    /// </summary>
    public static readonly TimeSpan TotpStepLifetime = TimeSpan.FromMinutes(4);

    /// <summary>
    /// How long a WebAuthn challenge's claim is remembered: longer than the longest challenge
    /// lifetime the security policy allows (<c>WebAuthnChallengeTtlSeconds</c>, clamped to 600
    /// seconds), so a challenge cannot be answered again while its options could still be cached.
    /// </summary>
    public static readonly TimeSpan WebAuthnChallengeLifetime = TimeSpan.FromMinutes(15);

    /// <summary>The <see cref="IReplayGuard"/> key marking TOTP time step <paramref name="timeStep"/> as used for <paramref name="userId"/>.</summary>
    /// <param name="userId">The account the code belongs to.</param>
    /// <param name="timeStep">The RFC 6238 time step the code matched.</param>
    public static string TotpStepKey(Guid userId, long timeStep) => $"totp:used:{userId:N}:{timeStep}";

    /// <summary>The <see cref="IReplayGuard"/> key marking a WebAuthn challenge as answered.</summary>
    /// <param name="challenge">The raw challenge bytes from the assertion options.</param>
    public static string WebAuthnChallengeKey(byte[] challenge) =>
        $"webauthn:challenge:{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(challenge))}";

    /// <summary>
    /// Claims TOTP time step <paramref name="timeStep"/> for <paramref name="userId"/>, so the code
    /// that matched it is accepted once, by whichever flow (sign-in, step-up, enrolment) presents
    /// it first.
    /// </summary>
    /// <param name="guard">The atomic single-use claim.</param>
    /// <param name="userId">The account the code belongs to.</param>
    /// <param name="timeStep">The time step the code matched.</param>
    /// <param name="ct">Cancellation.</param>
    /// <returns>True for the one caller that claimed the step; false when it was already used.</returns>
    public static Task<bool> TryClaimTotpStepAsync(IReplayGuard guard, Guid userId, long timeStep, CancellationToken ct = default)
        => guard.TryClaimAsync(TotpStepKey(userId, timeStep), TotpStepLifetime, ct);

    /// <summary>
    /// Claims a WebAuthn challenge, so one signed assertion over it completes one ceremony. Sign
    /// counters do not prevent this: many authenticators report zero, and two requests carrying
    /// the same assertion present the same counter.
    /// </summary>
    /// <param name="guard">The atomic single-use claim.</param>
    /// <param name="challenge">The raw challenge bytes from the assertion options.</param>
    /// <param name="ct">Cancellation.</param>
    /// <returns>True for the one caller that claimed the challenge; false when it was already answered.</returns>
    public static Task<bool> TryClaimWebAuthnChallengeAsync(IReplayGuard guard, byte[] challenge, CancellationToken ct = default)
        => guard.TryClaimAsync(WebAuthnChallengeKey(challenge), WebAuthnChallengeLifetime, ct);
}
