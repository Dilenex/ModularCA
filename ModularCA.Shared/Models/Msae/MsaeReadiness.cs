namespace ModularCA.Shared.Models.Msae;

/// <summary>How one precondition of Windows autoenrollment stands for a CA.</summary>
public enum MsaeReadinessState
{
    /// <summary>Met.</summary>
    Pass,
    /// <summary>Met, with something the operator should know.</summary>
    Warn,
    /// <summary>Not met; enrollment cannot work until it is.</summary>
    Fail,
    /// <summary>Not applicable given earlier answers, for example Kerberos checks when only username authentication is on.</summary>
    Skip,
}

/// <summary>Where the operator goes to fix a step: a console path, with the scope preset when the page is scope-filtered.</summary>
public sealed class MsaeReadinessFix
{
    /// <summary>Button text, e.g. "Open Protocol Config".</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Console path, e.g. <c>/authorities/protocols?ca=…</c>.</summary>
    public string Path { get; set; } = string.Empty;
}

/// <summary>One precondition, evaluated.</summary>
public sealed class MsaeReadinessStep
{
    /// <summary>Stable key, e.g. <c>msae-enabled</c>.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Short name as the checklist shows it.</summary>
    public string Title { get; set; } = string.Empty;

    public MsaeReadinessState State { get; set; }

    /// <summary>What was found, in a sentence an operator can act on.</summary>
    public string Detail { get; set; } = string.Empty;

    /// <summary>Supporting lines: one per realm, template or hostname that the step looked at.</summary>
    public List<string> Items { get; set; } = new();

    /// <summary>Where to fix it, when the state is not Pass.</summary>
    public MsaeReadinessFix? Fix { get; set; }
}

/// <summary>A forest bound to the tenant, as the readiness page lists it.</summary>
public sealed class MsaeReadinessRealm
{
    public Guid Id { get; set; }
    public string Realm { get; set; } = string.Empty;
    public string DnsDomain { get; set; } = string.Empty;
    public string ServicePrincipal { get; set; } = string.Empty;
}

/// <summary>Everything a Windows client needs from this CA, evaluated in dependency order.</summary>
public sealed class MsaeReadiness
{
    public Guid CaId { get; set; }
    public string CaLabel { get; set; } = string.Empty;
    public Guid? TenantId { get; set; }

    /// <summary>True when every step passes or warns.</summary>
    public bool Ready { get; set; }

    /// <summary>The policy service URL a client or Group Policy points at.</summary>
    public string CepUrl { get; set; } = string.Empty;

    /// <summary>The policy id a client records for this policy server; it is the CA's own id.</summary>
    public string PolicyId { get; set; } = string.Empty;

    public List<MsaeReadinessStep> Steps { get; set; } = new();

    /// <summary>The enabled forests bound to the CA's tenant, each of which can have a setup kit.</summary>
    public List<MsaeReadinessRealm> Realms { get; set; } = new();

    /// <summary>When the evaluation ran, UTC.</summary>
    public DateTime EvaluatedAt { get; set; }
}
