using System.Reflection;
using System.Reflection.Emit;
using Xunit;

namespace ModularCA.Tests.Enrollment;

/// <summary>
/// Seals the enrollment seam: a protocol service that has been migrated onto
/// <see cref="ModularCA.Core.Services.Enrollment.IEnrollmentPipeline"/> may not reach issuance,
/// profile resolution or enrollment authorization on its own. The test walks the type's fields,
/// its constructor and method signatures, and the IL of every method body it declares, resolving
/// each call, field access and type token; naming one of the forbidden services anywhere fails the
/// test with the offending member.
/// </summary>
/// <remarks>
/// <para>
/// This is what keeps the contract true after the migration ends. The duplicated middles were not
/// wrong because they were duplicated; they were wrong because a rule applied in five places can
/// be forgotten in a sixth, and nothing said so. A protocol that calls the pipeline for most of
/// the sequence and issues directly for one case would look exactly like a migrated one in review.
/// </para>
/// <para>
/// <see cref="ModularCA.Core.Services.RequestProfileValidationService"/> is deliberately not
/// forbidden. EST still asks it whether a request profile pins the values of a SAN type, which is
/// a question about policy the protocol's own SAN binding needs and not a step of the shared
/// middle. The three services listed here are the ones the middle owns.
/// </para>
/// <para>
/// The list is the protocols migrated so far, and grows with each one. It is declared rather than
/// derived — deriving it would make the test agree with whatever the code does, which is not a
/// test — and a name that no longer resolves fails the test, so a rename cannot quietly empty it.
/// </para>
/// </remarks>
public sealed class EnrollmentPipelineSeamArchitectureTests
{
    /// <summary>
    /// The protocol services already behind the pipeline, by full name. All five are here; a sixth
    /// protocol joins the list when it is written.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="ModularCA.Core.Services.Acme.AcmeOrderService"/> is listed for its finalize step
    /// alone, which is the only part of ACME the contract describes. The rest of the type is the
    /// order state machine, and the seam holds it to the same rule anyway: nothing in ACME may
    /// issue, resolve a profile or authorize an enrollment on its own.
    /// </para>
    /// <para>
    /// <see cref="ModularCA.Core.Services.Cmp.CmpService"/> is listed for <c>ir</c>, <c>cr</c> and
    /// <c>kur</c>, the three bodies that issue. Its revocation, confirmation and general-message
    /// paths produce no certificate and have no middle to share, and the seam holds them to the
    /// rule regardless: nothing in CMP may issue, resolve a profile or authorize an enrollment on
    /// its own.
    /// </para>
    /// <para>
    /// <see cref="ModularCA.Core.Services.Scep.ScepService"/> is listed for its PKCSReq path, which
    /// is the only one of its four messages that issues. <c>GetCACert</c> and <c>GetCACaps</c>
    /// publish configuration and <c>GetCertInitial</c> asks after a request that has already been
    /// through the middle; the seam holds all of them to the rule regardless.
    /// </para>
    /// </remarks>
    private static readonly string[] MigratedProtocolServices =
    [
        "ModularCA.Core.Services.Est.EstService",
        "ModularCA.Core.Services.Msae.MsaeEnrollmentService",
        "ModularCA.Core.Services.Acme.AcmeOrderService",
        "ModularCA.Core.Services.Cmp.CmpService",
        "ModularCA.Core.Services.Scep.ScepService",
    ];

    /// <summary>
    /// The services a migrated protocol may reach only through the pipeline: the interfaces and
    /// the concrete implementations both, so taking the class instead of the interface is not a
    /// way around the seam.
    /// </summary>
    private static readonly HashSet<string> ForbiddenTypes = new(StringComparer.Ordinal)
    {
        "ModularCA.Shared.Interfaces.ICertificateIssuanceService",
        "ModularCA.Core.Services.CertificateIssuanceService",
        "ModularCA.Core.Services.IProfileResolutionService",
        "ModularCA.Core.Services.ProfileResolutionService",
        "ModularCA.Core.Services.IEnrollmentAuthorizationService",
        "ModularCA.Core.Services.EnrollmentAuthorizationService",
    };

    private static Assembly CoreAssembly => typeof(ModularCA.Core.Services.CsrService).Assembly;

    [Fact]
    public void A_migrated_protocol_service_reaches_the_shared_middle_only_through_the_pipeline()
    {
        var offences = new List<string>();
        foreach (var name in MigratedProtocolServices)
        {
            var type = CoreAssembly.GetType(name, throwOnError: false);
            Assert.True(type != null, $"{name} no longer exists; update the enrollment seam's list.");
            Inspect(type!, offences);
        }

        Assert.True(offences.Count == 0,
            "A migrated protocol reaches the shared enrollment middle directly:\n  " + string.Join("\n  ", offences));
    }

    [Fact]
    public void The_seam_still_names_services_that_exist()
    {
        // A rename in Core must reach the forbidden list, or the seam would silently stop looking
        // for the renamed service and pass on nothing.
        foreach (var name in ForbiddenTypes)
        {
            var found = CoreAssembly.GetType(name, throwOnError: false)
                ?? typeof(ModularCA.Shared.Interfaces.ICertificateIssuanceService).Assembly.GetType(name, throwOnError: false);
            Assert.True(found != null, $"{name} no longer exists; update the enrollment seam.");
        }
    }

    [Fact]
    public void Every_migrated_protocol_service_takes_the_pipeline()
    {
        // The other half of the seam: not reaching the forbidden services is only meaningful if
        // the protocol reaches the pipeline instead. A service that had simply stopped enrolling
        // would pass the test above.
        foreach (var name in MigratedProtocolServices)
        {
            var type = CoreAssembly.GetType(name, throwOnError: false)!;
            var takesPipeline = type.GetConstructors()
                .SelectMany(c => c.GetParameters())
                .Any(p => p.ParameterType == typeof(ModularCA.Core.Services.Enrollment.IEnrollmentPipeline));
            Assert.True(takesPipeline, $"{name} does not take IEnrollmentPipeline.");
        }
    }

    private const BindingFlags Declared =
        BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    /// <summary>Walks one type's surface, its nested types, and every method body it declares.</summary>
    private static void Inspect(Type type, List<string> offences)
    {
        void Check(Type? t, string where)
        {
            foreach (var n in Names(t))
                if (ForbiddenTypes.Contains(n))
                    offences.Add($"{where}: references {n}");
        }

        foreach (var f in type.GetFields(Declared))
            Check(f.FieldType, $"{type.FullName}.{f.Name} (field)");
        foreach (var p in type.GetProperties(Declared))
            Check(p.PropertyType, $"{type.FullName}.{p.Name} (property)");
        foreach (var m in type.GetMethods(Declared))
        {
            Check(m.ReturnType, $"{type.FullName}.{m.Name} (return type)");
            foreach (var p in m.GetParameters())
                Check(p.ParameterType, $"{type.FullName}.{m.Name}({p.Name}) (parameter)");
            InspectBody(type, m, offences);
        }
        foreach (var c in type.GetConstructors(Declared))
        {
            foreach (var p in c.GetParameters())
                Check(p.ParameterType, $"{type.FullName}..ctor({p.Name}) (parameter)");
            InspectBody(type, c, offences);
        }

        // Lambdas and local functions compile into nested closure types, and a call made from one
        // of those is exactly as direct as a call made from the method that declares it.
        foreach (var nested in type.GetNestedTypes(Declared))
            Inspect(nested, offences);
    }

    /// <summary>The full names of a type and of every type it is built from.</summary>
    private static IEnumerable<string> Names(Type? t)
    {
        if (t == null) yield break;
        if (t.HasElementType)
        {
            foreach (var n in Names(t.GetElementType())) yield return n;
            yield break;
        }
        if (t.IsGenericParameter) yield break;
        if (t.IsGenericType && !t.IsGenericTypeDefinition)
        {
            foreach (var n in Names(t.GetGenericTypeDefinition())) yield return n;
            foreach (var arg in t.GetGenericArguments())
                foreach (var n in Names(arg)) yield return n;
            yield break;
        }
        if (t.FullName != null) yield return t.FullName;
    }

    /// <summary>
    /// Resolves every method, field and type token a method body carries and checks the type it
    /// names or belongs to. The IL walk is what makes this a seal rather than a signature check: a
    /// service resolved from a local and used once leaves no trace in any signature.
    /// </summary>
    private static void InspectBody(Type type, MethodBase method, List<string> offences)
    {
        MethodBody? body;
        try { body = method.GetMethodBody(); }
        catch (Exception) { return; }
        if (body == null) return;
        var il = body.GetILAsByteArray();
        if (il == null) return;

        var module = method.Module;
        var typeArgs = type.IsGenericType ? type.GetGenericArguments() : null;
        var methodArgs = method.IsGenericMethod ? method.GetGenericArguments() : null;
        var where = $"{type.FullName}.{method.Name} (body)";

        foreach (var (opcode, token) in Tokens(il))
        {
            MemberInfo? member = null;
            try
            {
                member = opcode.OperandType switch
                {
                    OperandType.InlineMethod => module.ResolveMethod(token, typeArgs, methodArgs),
                    OperandType.InlineField => module.ResolveField(token, typeArgs, methodArgs),
                    OperandType.InlineType => module.ResolveType(token, typeArgs, methodArgs),
                    OperandType.InlineTok => module.ResolveMember(token, typeArgs, methodArgs),
                    _ => null,
                };
            }
            catch (Exception)
            {
                // A token that does not resolve in this generic context names nothing we can check.
            }
            if (member == null) continue;

            if (member is Type named)
            {
                foreach (var n in Names(named))
                    if (ForbiddenTypes.Contains(n))
                        offences.Add($"{where}: names {n}");
                continue;
            }

            foreach (var n in Names(member.DeclaringType))
                if (ForbiddenTypes.Contains(n))
                    offences.Add($"{where}: calls {n}.{member.Name}");
        }
    }

    private static readonly Dictionary<short, OpCode> OpCodesByValue = typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!)
        .ToDictionary(o => o.Value, o => o);

    /// <summary>Walks the IL and yields each opcode that carries a metadata token, with the token.</summary>
    private static IEnumerable<(OpCode OpCode, int Token)> Tokens(byte[] il)
    {
        var i = 0;
        while (i < il.Length)
        {
            short value = il[i];
            i++;
            if (value == 0xFE)
            {
                value = (short)(0xFE00 | il[i]);
                i++;
            }
            if (!OpCodesByValue.TryGetValue(value, out var op))
                yield break; // Unknown opcode: stop rather than misread the rest.

            switch (op.OperandType)
            {
                case OperandType.InlineNone:
                    break;
                case OperandType.ShortInlineBrTarget:
                case OperandType.ShortInlineI:
                case OperandType.ShortInlineVar:
                    i += 1;
                    break;
                case OperandType.InlineVar:
                    i += 2;
                    break;
                case OperandType.InlineI8:
                case OperandType.InlineR:
                    i += 8;
                    break;
                case OperandType.InlineSwitch:
                    var count = BitConverter.ToInt32(il, i);
                    i += 4 + 4 * count;
                    break;
                case OperandType.InlineMethod:
                case OperandType.InlineField:
                case OperandType.InlineType:
                case OperandType.InlineTok:
                    yield return (op, BitConverter.ToInt32(il, i));
                    i += 4;
                    break;
                default:
                    i += 4;
                    break;
            }
        }
    }
}
