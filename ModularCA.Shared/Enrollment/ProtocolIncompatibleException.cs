namespace ModularCA.Shared.Enrollment;

/// <summary>
/// A protocol request refused because the protocol cannot run on the CA it addresses at all, as
/// <see cref="ProtocolCompatibility"/> judges it: today, SCEP on a CA whose key is not RSA. The
/// message is the advisory's sentence, safe to show the client.
/// </summary>
/// <remarks>
/// Not an <see cref="InvalidOperationException"/>, so the generic "operation failed" handling of
/// a protocol endpoint cannot swallow it and the client is told why.
/// </remarks>
public sealed class ProtocolIncompatibleException : Exception
{
    /// <summary>Constructs the refusal from the advisory that explains it.</summary>
    /// <param name="advisory">The reason code and the sentence.</param>
    public ProtocolIncompatibleException(ProtocolAdvisory advisory) : base(advisory.Message)
    {
        Advisory = advisory;
    }

    /// <summary>Why the protocol cannot run on this CA.</summary>
    public ProtocolAdvisory Advisory { get; }
}
