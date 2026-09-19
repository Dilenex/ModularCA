using System.Reflection;
using System.Reflection.Emit;
using Org.BouncyCastle.Crypto;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// Seals the signer seam: nothing in <c>ModularCA.Core</c>, <c>ModularCA.API</c>,
/// <c>ModularCA.Auth</c>, <c>ModularCA.Bootstrap</c> or <c>ModularCA.Signer</c> (the wire, the
/// remote client and the signer role's host) may reach a stored private key except through
/// <see cref="ModularCA.Shared.Signing.ISigningService"/>. The test loads the five
/// assemblies and walks every type they define: base types, interfaces, fields, properties,
/// events, constructor and method signatures, and the IL of every method body, resolving each
/// call, field access and type token. A reference to a handle type, to the keystore project's
/// registry or persistence, to a loader that returns key parameters, to one of the named key
/// members, or to any member of the keystore assembly whose return type is a BouncyCastle
/// private key fails the test with the offending type and member named.
/// </summary>
/// <remarks>
/// The IL walk is what makes this a seal rather than a signature check: a local variable or a
/// method call leaves no trace in a signature, and a handle obtained in a method body and used
/// there is exactly the leak the seam is meant to prevent. A reference through reflection
/// would still pass; that is not something this codebase does for keys, and a reviewer would
/// see it.
/// </remarks>
public sealed class SignerSeamArchitectureTests
{
    /// <summary>Types only the keystore project may name, by full name (nested types with <c>+</c>).</summary>
    private static readonly HashSet<string> ForbiddenTypes = new(StringComparer.Ordinal)
    {
        "ModularCA.Keystore.IPrivateKeyHandle",
        "ModularCA.Keystore.Adapters.SoftwarePrivateKeyHandle",
        "ModularCA.Keystore.Hsm.Pkcs11PrivateKeyHandle",
        "ModularCA.Keystore.Signing.ISignerKeyRegistry",
        "ModularCA.Keystore.Signing.MultiCARegistry",
        "ModularCA.Keystore.Signing.ISignerKeyPersistence",
        "ModularCA.Keystore.Signing.FileKeystorePersistence",
        "ModularCA.Keystore.Utils.StartupKeystoreLoader",
        "ModularCA.Keystore.Services.KeystoreService+CertKey",
        "ModularCA.Keystore.Services.KeystoreService+CertWithKey",
        // Should any of these come back into Shared, the name is still forbidden.
        "ModularCA.Shared.Interfaces.IPrivateKeyHandle",
    };

    /// <summary>Members that hand out a key or a handle, by name, whatever type declares them.</summary>
    private static readonly HashSet<string> ForbiddenMemberNames = new(StringComparer.Ordinal)
    {
        "LoadCertKeys",
        "MatchCertsWithKeys",
        "ExportPrivateKeyDer",
        "GetPrivateKeyFor",
        "LoadHsmSigners",
    };

    /// <summary>The BouncyCastle types a key comes as; a keystore-assembly member returning one is a leak.</summary>
    private static readonly HashSet<Type> KeyTypes = new() { typeof(AsymmetricKeyParameter), typeof(AsymmetricCipherKeyPair) };

    private const string KeystoreAssemblyName = "ModularCA.Keystore";

    /// <summary>
    /// The assemblies the seam is enforced on. Core, Auth, Bootstrap and Signer are referenced
    /// by the test project and named by a type each defines; the API is not referenced (its
    /// package graph is not the test project's) and is loaded by reflection from its build
    /// output for the same configuration the tests were built in.
    /// </summary>
    public static IEnumerable<object[]> SealedAssemblies()
    {
        yield return new object[] { typeof(ModularCA.Core.Services.CsrService).Assembly };
        yield return new object[] { LoadApiAssembly() };
        yield return new object[] { typeof(ModularCA.Auth.Services.DpopProofService).Assembly };
        yield return new object[] { typeof(ModularCA.Bootstrap.BackupRestore).Assembly };
        yield return new object[] { typeof(ModularCA.Signer.Wire.WireMapping).Assembly };
    }

    /// <summary>
    /// Finds <c>ModularCA.API/bin/&lt;configuration&gt;/&lt;tfm&gt;/ModularCA.API.dll</c> above the
    /// test output directory and loads it. The API must have been built in the same
    /// configuration; the message says so when it was not, rather than passing on nothing.
    /// </summary>
    private static Assembly LoadApiAssembly()
    {
        var testDir = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        // tests/ModularCA.Tests/bin/<configuration>/<tfm>/
        var configuration = testDir.Parent?.Name ?? "Debug";
        var repoRoot = testDir;
        while (repoRoot != null && !Directory.Exists(Path.Combine(repoRoot.FullName, "ModularCA.API")))
            repoRoot = repoRoot.Parent;
        Assert.True(repoRoot != null, $"The repository root was not found above {testDir.FullName}.");

        var apiProject = Path.Combine(repoRoot!.FullName, "ModularCA.API");
        var apiDll = Path.Combine(apiProject, "bin", configuration, testDir.Name, "ModularCA.API.dll");
        Assert.True(File.Exists(apiDll), $"{apiDll} does not exist; build ModularCA.API in the {configuration} configuration before running the seam test.");

        // A stale binary would let a leak in the source pass unseen, so a source file newer
        // than the assembly fails the test instead of inspecting yesterday's build.
        var builtAt = File.GetLastWriteTimeUtc(apiDll);
        var newerSource = Directory.EnumerateFiles(apiProject, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}") && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .FirstOrDefault(f => File.GetLastWriteTimeUtc(f) > builtAt);
        Assert.True(newerSource == null, $"{newerSource} is newer than {apiDll}; rebuild ModularCA.API before running the seam test.");

        return Assembly.LoadFrom(apiDll);
    }

    [Theory]
    [MemberData(nameof(SealedAssemblies))]
    public void Nothing_outside_the_keystore_project_reaches_a_private_key_handle(Assembly assembly)
    {
        var offences = new List<string>();
        foreach (var type in TypesOf(assembly))
            Inspect(type, offences);

        Assert.True(offences.Count == 0,
            $"{assembly.GetName().Name} reaches a private key outside the signer:\n  " + string.Join("\n  ", offences));
    }

    [Fact]
    public void The_seal_covers_the_five_assemblies_the_design_names()
    {
        var names = SealedAssemblies().Select(a => ((Assembly)a[0]).GetName().Name!).ToHashSet();
        Assert.Equal(new HashSet<string> { "ModularCA.Core", "ModularCA.API", "ModularCA.Auth", "ModularCA.Bootstrap", "ModularCA.Signer" }, names);
    }

    [Fact]
    public void The_forbidden_types_still_exist_where_the_seal_expects_them()
    {
        // A rename in the keystore project must reach this list, or the seal would silently
        // stop checking for the renamed type.
        var keystore = typeof(ModularCA.Keystore.Signing.InProcessSigningService).Assembly;
        foreach (var name in ForbiddenTypes.Where(n => n.StartsWith("ModularCA.Keystore.", StringComparison.Ordinal)))
            Assert.True(keystore.GetType(name, throwOnError: false) != null, $"{name} no longer exists; update the seal.");
    }

    /// <summary>
    /// Every type the assembly defines. A type that cannot be loaded cannot be inspected, and a
    /// seal with holes in it is not a seal, so loader failures fail the test with their reasons.
    /// </summary>
    private static IEnumerable<Type> TypesOf(Assembly assembly)
    {
        try
        {
            return assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            var reasons = ex.LoaderExceptions.Where(e => e != null).Select(e => e!.Message).Distinct().Take(5);
            Assert.Fail($"{assembly.GetName().Name}: {ex.Types.Count(t => t == null)} type(s) could not be loaded for inspection:\n  " + string.Join("\n  ", reasons));
            throw;
        }
    }

    private const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    /// <summary>Walks one type's surface and every method body it declares.</summary>
    private static void Inspect(Type type, List<string> offences)
    {
        void Check(Type? t, string where)
        {
            foreach (var name in Names(t))
            {
                if (ForbiddenTypes.Contains(name))
                    offences.Add($"{where}: references {name}");
            }
        }

        Check(type.BaseType, $"{type.FullName} (base type)");
        foreach (var i in type.GetInterfaces())
            Check(i, $"{type.FullName} (interface)");
        foreach (var f in type.GetFields(Declared))
            Check(f.FieldType, $"{type.FullName}.{f.Name} (field)");
        foreach (var p in type.GetProperties(Declared))
            Check(p.PropertyType, $"{type.FullName}.{p.Name} (property)");
        foreach (var e in type.GetEvents(Declared))
            Check(e.EventHandlerType, $"{type.FullName}.{e.Name} (event)");
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
    }

    /// <summary>The full names of a type and of every type it is built from: element types, generic arguments.</summary>
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
    /// Resolves every method, field and type token a method body carries and checks each: the
    /// type it names or belongs to, the member's name, and, for a keystore-assembly member,
    /// whether its return type is a key.
    /// </summary>
    private static void InspectBody(Type type, MethodBase method, List<string> offences)
    {
        MethodBody? body;
        try
        {
            body = method.GetMethodBody();
        }
        catch (Exception)
        {
            return;
        }
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
            CheckMember(member, where, offences);
        }
    }

    private static void CheckMember(MemberInfo member, string where, List<string> offences)
    {
        if (member is Type t)
        {
            foreach (var name in Names(t))
                if (ForbiddenTypes.Contains(name))
                    offences.Add($"{where}: names {name}");
            return;
        }

        foreach (var name in Names(member.DeclaringType))
            if (ForbiddenTypes.Contains(name))
                offences.Add($"{where}: uses {name}.{member.Name}");

        if (ForbiddenMemberNames.Contains(member.Name))
            offences.Add($"{where}: calls {member.DeclaringType?.FullName}.{member.Name}");

        var declaredInKeystore = member.DeclaringType?.Assembly.GetName().Name == KeystoreAssemblyName;
        if (!declaredInKeystore) return;
        var returns = member switch
        {
            MethodInfo m => m.ReturnType,
            FieldInfo f => f.FieldType,
            PropertyInfo p => p.PropertyType,
            _ => null,
        };
        if (returns != null && Names(returns).Any(n => KeyTypes.Any(k => k.FullName == n)))
            offences.Add($"{where}: {member.DeclaringType!.FullName}.{member.Name} hands out a {returns.Name}");
    }

    private static readonly Dictionary<short, OpCode> OpCodesByValue = typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode))
        .Select(f => (OpCode)f.GetValue(null)!)
        .ToDictionary(o => o.Value, o => o);

    /// <summary>Walks the IL and yields each opcode that carries a metadata token with the token.</summary>
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
                    i += 4; // InlineI, InlineBrTarget, InlineSig, InlineString, ShortInlineR
                    break;
            }
        }
    }
}
