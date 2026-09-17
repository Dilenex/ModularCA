using ModularCA.Shared.Signing;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The contract suite bound to <see cref="ModularCA.Signer.Client.RemoteSigningService"/>
/// talking to the real gRPC signer hosted in the test process over loopback with mutual TLS,
/// the identities generated the way <c>--init-identity</c> generates them. Every policy row,
/// audit row and refusal reason the in-process suite asserts must hold across the wire.
/// </summary>
public sealed class RemoteSigningServiceTests : SigningServiceContractTests
{
    internal override ISigningService CreateSigner(SignerTestWorld world) => HostedSigners.For(world);

    protected override string ExpectedBackend => SignerHealth.SoftwareBackend;

    internal override void AssertPersisted(SignerTestWorld world, byte[] certificateDer)
        => Assert.Contains(world.Persistence.Appended, p => p.CertificateDer.AsSpan().SequenceEqual(certificateDer));
}
