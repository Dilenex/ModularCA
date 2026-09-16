namespace ModularCA.Shared.Enums;

/// <summary>How a Kerberos realm key arrived in ModularCA. Recorded for the audit trail; never affects acceptance.</summary>
public enum KerberosKeySource
{
    /// <summary>Parsed from an uploaded keytab file, which was not kept.</summary>
    Keytab = 0,
    /// <summary>Derived from the service account's password, which was not kept.</summary>
    Password = 1,
    /// <summary>Derived from a password ModularCA generated and showed once.</summary>
    Generated = 2,
}
