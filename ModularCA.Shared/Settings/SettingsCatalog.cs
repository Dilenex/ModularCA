using System.Collections;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Shared.Settings;

/// <summary>One setting: a leaf property of <see cref="SystemConfig"/>, under the name it is stored by.</summary>
/// <param name="Key">The stored name: the property path joined by underscores, for example <c>Acme_Http01_MaxAddresses</c>.</param>
/// <param name="Path">The same path with dots, as <c>config.yaml</c> and the documentation write it.</param>
/// <param name="Section">The first segment of the path.</param>
/// <param name="ValueType">The CLR type of the value.</param>
/// <param name="AllowsNull">Whether the value may be null.</param>
/// <param name="Class">Where the setting lives.</param>
/// <param name="Reload">How a change reloads.</param>
/// <param name="Secret">How a secret is kept; <see cref="SettingSecretKind.None"/> otherwise.</param>
public sealed record SettingDefinition(
    string Key, string Path, string Section, Type ValueType, bool AllowsNull,
    SettingClass Class, SettingReload Reload, SettingSecretKind Secret)
{
    internal IReadOnlyList<PropertyInfo> Properties { get; init; } = [];

    /// <summary>Whether the setting is kept in the database: instance-wide settings and secrets.</summary>
    public bool StoredInDatabase => Class is SettingClass.InstanceWide or SettingClass.Secret;
}

/// <summary>
/// Every setting in <see cref="SystemConfig"/>, built once by reflection. A setting is a leaf: a
/// property whose type is not itself a group of settings. A list or a dictionary is one leaf and
/// is stored whole, so a change replaces it and never merges into the default.
/// </summary>
public static class SettingsCatalog
{
    /// <summary>The separator between the segments of a key.</summary>
    public const char KeySeparator = '_';

    /// <summary>
    /// How a setting's value is written and read as JSON: property names as declared, enums by
    /// name, and an unknown member of a list element refused instead of dropped.
    /// </summary>
    public static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = null,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() },
    };

    private static readonly Lazy<IReadOnlyList<SettingDefinition>> All = new(() => Build(typeof(SystemConfig)));

    private static readonly Lazy<IReadOnlyDictionary<string, SettingDefinition>> ByKey = new(() =>
        All.Value.ToDictionary(d => d.Key, StringComparer.Ordinal));

    /// <summary>Every setting, in declaration order.</summary>
    public static IReadOnlyList<SettingDefinition> Definitions => All.Value;

    /// <summary>The setting stored under <paramref name="key"/>, or null when there is none. Keys are case-sensitive.</summary>
    public static SettingDefinition? Find(string key) => ByKey.Value.GetValueOrDefault(key);

    /// <summary>The value of <paramref name="definition"/> in <paramref name="config"/>, as JSON; null for a null value.</summary>
    public static JsonNode? Read(SystemConfig config, SettingDefinition definition)
    {
        object? current = config;
        foreach (var property in definition.Properties)
        {
            current = property.GetValue(current);
            if (current == null) return null;
        }
        return JsonSerializer.SerializeToNode(current, definition.ValueType, JsonOptions);
    }

    /// <summary>
    /// The one spelling of <paramref name="value"/> for <paramref name="definition"/>: through
    /// the setting's own type and back, with the members of every object in name order. Two
    /// values are the same value exactly when their canonical JSON is the same text, which a
    /// dictionary's own order would not give (<c>Scheduler_JobTimeouts</c> is one).
    /// <paramref name="value"/> must have passed <see cref="Problem"/>.
    /// </summary>
    public static string CanonicalJson(SettingDefinition definition, JsonNode? value)
    {
        var typed = value.Deserialize(definition.ValueType, JsonOptions);
        return Sorted(JsonSerializer.SerializeToNode(typed, definition.ValueType, JsonOptions))?.ToJsonString() ?? "null";
    }

    private static JsonNode? Sorted(JsonNode? node) => node switch
    {
        JsonObject o => new JsonObject(o.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => KeyValuePair.Create(p.Key, Sorted(p.Value?.DeepClone())))),
        JsonArray a => new JsonArray(a.Select(item => Sorted(item?.DeepClone())).ToArray()),
        _ => node,
    };

    /// <summary>
    /// Sets <paramref name="definition"/> in <paramref name="config"/> to <paramref name="value"/>,
    /// which must have passed <see cref="Problem"/>.
    /// </summary>
    public static void Apply(SystemConfig config, SettingDefinition definition, JsonNode? value)
    {
        object target = config;
        foreach (var property in definition.Properties.Take(definition.Properties.Count - 1))
        {
            var next = property.GetValue(target);
            if (next == null)
            {
                next = Activator.CreateInstance(property.PropertyType)!;
                property.SetValue(target, next);
            }
            target = next;
        }
        definition.Properties[^1].SetValue(target, value.Deserialize(definition.ValueType, JsonOptions));
    }

    /// <summary>
    /// Why <paramref name="value"/> cannot be the value of <paramref name="definition"/>, or null
    /// when it can: it has to be JSON of the setting's type, and null only where the setting
    /// allows it. This is the shape of the value and nothing more; what a value may be is the
    /// section's own rule.
    /// </summary>
    public static string? Problem(SettingDefinition definition, JsonNode? value)
    {
        if (value == null)
            return definition.AllowsNull ? null : $"{definition.Key} cannot be null.";
        try
        {
            return value.Deserialize(definition.ValueType, JsonOptions) == null
                ? $"{definition.Key} cannot be null."
                : null;
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException or FormatException)
        {
            return $"{definition.Key} takes a value of type {Describe(definition.ValueType)}.";
        }
    }

    private static string Describe(Type type)
    {
        var underlying = Nullable.GetUnderlyingType(type);
        if (underlying != null) return Describe(underlying);
        if (type == typeof(string)) return "text";
        if (type == typeof(bool)) return "true or false";
        if (type == typeof(Guid)) return "a GUID";
        if (type.IsEnum) return "one of " + string.Join(", ", Enum.GetNames(type));
        if (type.IsPrimitive) return "a number";
        if (typeof(IDictionary).IsAssignableFrom(type)) return "an object";
        if (typeof(IEnumerable).IsAssignableFrom(type)) return "a list";
        return type.Name;
    }

    private static IReadOnlyList<SettingDefinition> Build(Type root)
    {
        var definitions = new List<SettingDefinition>();
        var nullability = new NullabilityInfoContext();
        Walk(root, [], definitions, nullability);

        var duplicate = definitions.GroupBy(d => d.Key, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1);
        if (duplicate != null)
            throw new InvalidOperationException($"Two settings share the key {duplicate.Key}: {string.Join(", ", duplicate.Select(d => d.Path))}.");
        return definitions;
    }

    private static void Walk(Type type, List<PropertyInfo> path, List<SettingDefinition> into, NullabilityInfoContext nullability)
    {
        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                     .Where(p => p.CanRead && p.CanWrite && p.GetIndexParameters().Length == 0)
                     .OrderBy(p => p.MetadataToken))
        {
            if (property.Name.Contains(KeySeparator))
                throw new InvalidOperationException(
                    $"{type.Name}.{property.Name} cannot be a setting: its name contains the key separator '{KeySeparator}'.");

            var segments = path.Append(property).ToList();
            var attribute = property.GetCustomAttribute<SettingAttribute>();

            if (IsGroup(property.PropertyType))
            {
                if (attribute != null)
                    throw new InvalidOperationException(
                        $"{Dotted(segments)} is a group of settings; [Setting] belongs on its leaves.");
                if (path.Any(p => p.PropertyType == property.PropertyType))
                    throw new InvalidOperationException($"{Dotted(segments)} nests its own type.");
                Walk(property.PropertyType, segments, into, nullability);
                continue;
            }

            if (attribute == null)
                throw new InvalidOperationException(
                    $"{Dotted(segments)} has no [Setting]. Every setting declares where it lives and how it reloads.");
            if ((attribute.Class == SettingClass.Secret) != (attribute.Secret != SettingSecretKind.None))
                throw new InvalidOperationException(
                    $"{Dotted(segments)}: a setting names how its secret is kept exactly when its class is Secret.");

            var allowsNull = Nullable.GetUnderlyingType(property.PropertyType) != null
                || (!property.PropertyType.IsValueType && nullability.Create(property).WriteState == NullabilityState.Nullable);

            into.Add(new SettingDefinition(
                string.Join(KeySeparator, segments.Select(p => p.Name)), Dotted(segments), segments[0].Name,
                property.PropertyType, allowsNull, attribute.Class, attribute.Reload, attribute.Secret)
            {
                Properties = segments,
            });
        }
    }

    private static string Dotted(IEnumerable<PropertyInfo> segments) => string.Join('.', segments.Select(p => p.Name));

    /// <summary>A group is a settings class of our own; anything else, lists and dictionaries of them included, is a value.</summary>
    private static bool IsGroup(Type type) =>
        type.IsClass
        && type != typeof(string)
        && !typeof(IEnumerable).IsAssignableFrom(type)
        && type.Assembly == typeof(SystemConfig).Assembly;
}
