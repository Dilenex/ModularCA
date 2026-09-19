using System.Reflection;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Ingress;

/// <summary>
/// The ingress types of the API assembly, loaded by reflection as the role tests load it: the
/// test project does not reference the host. Every call goes through here so a rename in the
/// API fails one place with the name.
/// </summary>
internal static class IngressApi
{
    /// <summary><c>ModularCA.API.Ingress.IngressProxyConfigProvider</c>.</summary>
    public static Type Provider => ApiAssembly.TypeNamed("ModularCA.API.Ingress.IngressProxyConfigProvider");

    /// <summary><c>ModularCA.API.Ingress.IngressHosting</c>.</summary>
    public static Type Hosting => ApiAssembly.TypeNamed("ModularCA.API.Ingress.IngressHosting");

    /// <summary><c>ModularCA.API.Ingress.UpstreamTrustPolicy</c>.</summary>
    public static Type TrustPolicy => ApiAssembly.TypeNamed("ModularCA.API.Ingress.UpstreamTrustPolicy");

    /// <summary><c>ModularCA.API.Ingress.UpstreamTrustMode</c>.</summary>
    public static Type TrustMode => ApiAssembly.TypeNamed("ModularCA.API.Ingress.UpstreamTrustMode");

    /// <summary><c>ModularCA.API.Ingress.IngressListenerMiddleware</c>.</summary>
    public static Type ListenerMiddleware => ApiAssembly.TypeNamed("ModularCA.API.Ingress.IngressListenerMiddleware");

    /// <summary>Invokes a public static method by name, unwrapping the invocation exception.</summary>
    public static object? Call(Type type, string method, params object?[] args)
    {
        var m = type.GetMethod(method, BindingFlags.Public | BindingFlags.Static);
        Assert.True(m != null, $"{type.FullName}.{method} is not a public static method.");
        try
        {
            return m!.Invoke(null, args);
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }

    /// <summary>Invokes a public instance method by name, unwrapping the invocation exception.</summary>
    public static object? Call(object instance, string method, params object?[] args)
    {
        var candidates = instance.GetType().GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.Name == method && m.GetParameters().Length == args.Length)
            .ToList();
        Assert.True(candidates.Count > 0, $"{instance.GetType().FullName}.{method}/{args.Length} is not a public instance method.");
        var m = candidates.Count == 1 ? candidates[0] : candidates.First(c => Matches(c, args));
        try
        {
            return m.Invoke(instance, args);
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }

    private static bool Matches(MethodInfo method, object?[] args)
    {
        var parameters = method.GetParameters();
        for (var i = 0; i < parameters.Length; i++)
        {
            if (args[i] == null)
            {
                if (parameters[i].ParameterType.IsValueType && Nullable.GetUnderlyingType(parameters[i].ParameterType) == null)
                    return false;
                continue;
            }
            if (!parameters[i].ParameterType.IsInstanceOfType(args[i]))
                return false;
        }
        return true;
    }

    /// <summary>The string constant <paramref name="name"/> declared on the provider.</summary>
    public static string ProviderConstant(string name)
        => (string)Provider.GetField(name, BindingFlags.Public | BindingFlags.Static)!.GetRawConstantValue()!;
}
