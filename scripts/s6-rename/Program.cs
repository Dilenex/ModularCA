using System.Text;
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.MSBuild;
using Microsoft.CodeAnalysis.Rename;
using Microsoft.CodeAnalysis.Text;

// Applies the renames in a map file to ModularCA.sln and writes the changed files. Map lines:
//   <documentation comment id> => <new name>     e.g.  P:ModularCA.Shared.Entities.RoleEntity.TenantId => SpaceId
//   exclude: <repo-relative path prefix>          a path the renames must not touch; touching one aborts with nothing written
//   auto: <Old> => <New>                          also rename every other source symbol whose name contains Old, by substitution
//                                                 (Old, old and OLD); locals and parameters included
//   keep: <documentation comment id>              a symbol the auto rule must leave alone
//   comments: on                                  apply the auto rule to comment text too, except the words listed in keep-word:
//   keep-word: <word>                             a word in a comment the comment rule must leave alone
//   refs-only: <repo-relative path prefix>        rewrite only references to symbols declared elsewhere; nothing declared
//                                                 there is renamed and its comments are left alone
//   word: <old> => <new>                          a phrase in a comment to reword first (exact case)
//   # comment
// A symbol that is not found aborts with nothing written. With --list, prints what the auto rule
// would rename (every symbol that is not a local or a parameter) and writes nothing.
//
// Without an auto: line the map is applied with Roslyn's rename engine, one symbol at a time.
// With one, the renames are a pure function of the old name, so every reference is rewritten in a
// single pass over the original solution. The auto rule never renames:
//   - a symbol declared in an excluded path, in generated code or in metadata;
//   - a member of an anonymous type (its name is a JSON name);
//   - a parameter of a public controller action, or one with a [From*] attribute (bound by name);
//   - a record's positional parameter whose property is kept.

var listOnly = args.Contains("--list");
var mapArg = args.Where(a => a != "--list").ToArray();
if (mapArg.Length != 1)
{
    Console.Error.WriteLine("usage: S6Rename [--list] <map file>");
    return 2;
}

var mapPath = Path.GetFullPath(mapArg[0]);
var root = FindRoot(Path.GetDirectoryName(mapPath)!);
var renames = new List<(string Id, string NewName)>();
var excluded = new List<string>();
var refsOnly = new List<string>();
var autoRules = new List<(string From, string To)>();
var keeps = new HashSet<string>(StringComparer.Ordinal);
var keepWords = new List<string>();
var words = new List<(string From, string To)>();
var comments = false;
foreach (var raw in File.ReadAllLines(mapPath))
{
    var line = raw.Trim();
    if (line.Length == 0 || line.StartsWith('#'))
        continue;
    if (TryDirective(line, "exclude:", out var value))
        excluded.Add(value.Replace('\\', '/'));
    else if (TryDirective(line, "refs-only:", out value))
        refsOnly.Add(value.Replace('\\', '/'));
    else if (TryDirective(line, "keep:", out value))
        keeps.Add(value);
    else if (TryDirective(line, "keep-word:", out value))
        keepWords.Add(value);
    else if (TryDirective(line, "word:", out value))
    {
        var rule = value.Split("=>", 2, StringSplitOptions.TrimEntries);
        if (rule.Length != 2 || rule[0].Length == 0 || rule[1].Length == 0)
        {
            Console.Error.WriteLine($"Bad map line: {raw}");
            return 2;
        }
        words.Add((rule[0], rule[1]));
    }
    else if (TryDirective(line, "comments:", out value))
        comments = value == "on";
    else if (TryDirective(line, "auto:", out value))
    {
        var rule = value.Split("=>", 2, StringSplitOptions.TrimEntries);
        if (rule.Length != 2 || rule[0].Length == 0 || rule[1].Length == 0)
        {
            Console.Error.WriteLine($"Bad map line: {raw}");
            return 2;
        }
        autoRules.Add((rule[0], rule[1]));
    }
    else
    {
        var parts = line.Split("=>", 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || parts[0].Length < 3 || parts[0][1] != ':' || parts[1].Length == 0)
        {
            Console.Error.WriteLine($"Bad map line: {raw}");
            return 2;
        }
        renames.Add((parts[0], parts[1]));
    }
}

MSBuildLocator.RegisterDefaults();
using var workspace = MSBuildWorkspace.Create();
var original = await workspace.OpenSolutionAsync(Path.Combine(root, "ModularCA.sln"));
foreach (var diagnostic in workspace.Diagnostics.Where(d => d.Kind == WorkspaceDiagnosticKind.Failure && !d.Message.Contains(".esproj")))
    Console.Error.WriteLine($"workspace: {diagnostic.Message}");

bool IsExcluded(string path) => UnderAny(path, excluded);
bool IsRefsOnly(string path) => UnderAny(path, refsOnly);
bool UnderAny(string path, List<string> prefixes)
{
    var rel = Path.GetRelativePath(root, path).Replace('\\', '/');
    return prefixes.Any(prefix => rel.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
}

if (autoRules.Count > 0)
    return await new AutoRename(original, root, renames, autoRules, keeps, keepWords, words, comments, IsExcluded, IsRefsOnly, listOnly).RunAsync();

var solution = original;
foreach (var (id, _) in renames)
{
    var symbol = await FindSourceSymbolAsync(solution, id);
    if (symbol is null)
    {
        Console.Error.WriteLine($"Not found in source: {id}. Nothing was written.");
        return 1;
    }
    solution = await NameInferredAnonymousMembersAsync(solution, symbol, root);
}

foreach (var (id, newName) in renames)
{
    var symbol = (await FindSourceSymbolAsync(solution, id))!;
    solution = await Renamer.RenameSymbolAsync(solution, symbol, new SymbolRenameOptions(), newName);
    Console.WriteLine($"renamed {id} -> {newName}");
}

var written = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
foreach (var projectChanges in solution.GetChanges(original).GetProjectChanges())
{
    foreach (var documentId in projectChanges.GetChangedDocuments())
    {
        var document = solution.GetDocument(documentId)!;
        if (document.FilePath is not { } path || written.ContainsKey(path))
            continue;
        written[path] = (await document.GetTextAsync()).ToString();
    }
}

var touchedExcluded = written.Keys.Where(IsExcluded).Select(p => Path.GetRelativePath(root, p)).ToList();
if (touchedExcluded.Count > 0)
{
    Console.Error.WriteLine("The renames would change excluded files; nothing was written:");
    foreach (var rel in touchedExcluded)
        Console.Error.WriteLine($"  {rel}");
    return 1;
}

foreach (var (path, text) in written)
    WritePreservingBom(path, text);
Console.WriteLine($"{written.Count} file(s) changed.");
return 0;

static bool TryDirective(string line, string prefix, out string value)
{
    value = line.StartsWith(prefix, StringComparison.Ordinal) ? line[prefix.Length..].Trim() : "";
    return value.Length > 0;
}

static async Task<ISymbol?> FindSourceSymbolAsync(Solution solution, string id)
{
    foreach (var project in solution.Projects.Where(p => p.Language == LanguageNames.CSharp))
    {
        var compilation = await project.GetCompilationAsync();
        if (compilation is null)
            continue;
        var symbol = DocumentationCommentId.GetFirstSymbolForDeclarationId(id, compilation);
        if (symbol is not null && symbol.Locations.Any(l => l.IsInSource))
            return symbol;
    }
    return null;
}

// An anonymous object member whose name is inferred from a renamed symbol (new { x.TenantId })
// would take the new name, changing the JSON name of any response built from it and breaking every
// later read of the member. Before renaming, each is given its current name explicitly
// (new { TenantId = x.TenantId }), so the rename changes only the right-hand side. Members inside
// HasIndex/HasKey are left inferred: EF reads their expressions, not their names.
static async Task<Solution> NameInferredAnonymousMembersAsync(Solution solution, ISymbol symbol, string root)
{
    var byDocument = new Dictionary<DocumentId, List<AnonymousObjectMemberDeclaratorSyntax>>();
    foreach (var found in await Microsoft.CodeAnalysis.FindSymbols.SymbolFinder.FindReferencesAsync(symbol, solution))
    {
        foreach (var location in found.Locations)
        {
            var syntaxRoot = await location.Document.GetSyntaxRootAsync();
            var node = syntaxRoot!.FindNode(location.Location.SourceSpan, getInnermostNodeForTie: true);
            var declarator = node.AncestorsAndSelf().OfType<AnonymousObjectMemberDeclaratorSyntax>().FirstOrDefault();
            if (declarator is null || !Syntax.IsInferredFrom(declarator, location.Location.SourceSpan))
                continue;
            if (!byDocument.TryGetValue(location.Document.Id, out var list))
                byDocument[location.Document.Id] = list = [];
            if (!list.Contains(declarator))
                list.Add(declarator);
            var line = location.Location.GetLineSpan();
            Console.WriteLine($"  named: {Path.GetRelativePath(root, line.Path)}:{line.StartLinePosition.Line + 1}: {declarator}");
        }
    }
    foreach (var (documentId, declarators) in byDocument)
    {
        var document = solution.GetDocument(documentId)!;
        var syntaxRoot = await document.GetSyntaxRootAsync();
        var rewritten = syntaxRoot!.ReplaceNodes(declarators, (_, current) =>
            current.WithExpression(current.Expression.WithoutLeadingTrivia())
                .WithNameEquals(SyntaxFactory.NameEquals(
                    SyntaxFactory.IdentifierName(symbol.Name),
                    SyntaxFactory.Token(SyntaxKind.EqualsToken).WithLeadingTrivia(SyntaxFactory.Space).WithTrailingTrivia(SyntaxFactory.Space)))
                .WithLeadingTrivia(current.GetLeadingTrivia()));
        solution = solution.WithDocumentSyntaxRoot(documentId, rewritten);
    }
    return solution;
}

static void WritePreservingBom(string path, string text)
{
    var bytes = File.ReadAllBytes(path);
    var bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
    File.WriteAllText(path, text, new UTF8Encoding(bom));
}

static string FindRoot(string start)
{
    for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
        if (File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            return dir.FullName;
    throw new InvalidOperationException("ModularCA.sln not found above the map file.");
}

static class Syntax
{
    /// <summary>
    /// Whether <paramref name="declarator"/> takes its member name from the name at <paramref name="span"/>
    /// (new { x.TenantId }), outside an EF HasIndex/HasKey/HasAlternateKey call.
    /// </summary>
    public static bool IsInferredFrom(AnonymousObjectMemberDeclaratorSyntax declarator, TextSpan span)
    {
        if (declarator.NameEquals is not null || TerminalName(declarator.Expression)?.Span != span)
            return false;
        return !declarator.Ancestors().OfType<InvocationExpressionSyntax>().Any(i =>
            i.Expression is MemberAccessExpressionSyntax { Name.Identifier.ValueText: "HasIndex" or "HasKey" or "HasAlternateKey" });
    }

    // The name an inferred anonymous member takes from its expression: the last name of a member access.
    private static SimpleNameSyntax? TerminalName(ExpressionSyntax expression) => expression switch
    {
        MemberAccessExpressionSyntax access => access.Name,
        SimpleNameSyntax name => name,
        PostfixUnaryExpressionSyntax { Operand: var operand } => TerminalName(operand),
        _ => null,
    };
}

/// <summary>
/// The auto mode: every reference to a renamed symbol is found by binding each identifier token of
/// the original solution, and rewritten by text edits applied in one pass.
/// </summary>
sealed class AutoRename(
    Solution solution, string root, List<(string Id, string NewName)> explicitRenames,
    List<(string From, string To)> rules, HashSet<string> keeps, List<string> keepWords,
    List<(string From, string To)> words, bool comments,
    Func<string, bool> isExcluded, Func<string, bool> isRefsOnly, bool listOnly)
{
    private readonly Dictionary<string, string> _explicit = explicitRenames.ToDictionary(r => r.Id, r => r.NewName, StringComparer.Ordinal);
    private readonly Dictionary<string, List<(TextSpan Span, string Text)>> _edits = new(StringComparer.OrdinalIgnoreCase);
    private readonly SortedDictionary<string, string> _renamed = new(StringComparer.Ordinal);
    private readonly HashSet<string> _foundExplicit = new(StringComparer.Ordinal);
    private readonly HashSet<string> _explicitNames = explicitRenames
        .Select(r => r.Id.Split('(')[0].Split('.')[^1].Split('`')[0])
        .SelectMany(n => new[] { n, n.EndsWith("Attribute", StringComparison.Ordinal) ? n[..^"Attribute".Length] : n })
        .ToHashSet(StringComparer.Ordinal);
    private readonly List<string> _problems = [];
    private int _localRenames;

    /// <summary>Runs the rename, or with --list prints it.</summary>
    public async Task<int> RunAsync()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var project in solution.Projects.Where(p => p.Language == LanguageNames.CSharp))
        {
            foreach (var document in project.Documents)
            {
                if (document.FilePath is not { } path || !seen.Add(path) || IsGenerated(path))
                    continue;
                var model = (await document.GetSemanticModelAsync())!;
                var syntaxRoot = await document.GetSyntaxRootAsync();
                await ScanAsync(path, model, syntaxRoot!, isExcluded(path), isRefsOnly(path));
            }
        }

        foreach (var id in _explicit.Keys.Where(id => !_foundExplicit.Contains(id)))
            _problems.Add($"not found in source: {id}");

        foreach (var (id, newName) in _renamed)
            Console.WriteLine($"rename {id} -> {newName}");
        Console.WriteLine($"{_renamed.Count} declared symbol(s), {_localRenames} local or parameter reference(s).");

        if (_problems.Count > 0)
        {
            Console.Error.WriteLine("Problems; nothing was written:");
            foreach (var problem in _problems.Distinct())
                Console.Error.WriteLine($"  {problem}");
            return 1;
        }
        if (listOnly)
            return 0;

        foreach (var (path, edits) in _edits.OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase))
        {
            var text = SourceText.From(await File.ReadAllTextAsync(path));
            var changes = edits.Distinct().OrderBy(e => e.Span.Start).Select(e => new TextChange(e.Span, e.Text)).ToList();
            var updated = text.WithChanges(changes).ToString();
            if (updated == text.ToString())
                continue;
            WriteKeepingBom(path, updated);
            Console.WriteLine($"wrote {Path.GetRelativePath(root, path)}");
        }
        Console.WriteLine($"{_edits.Count} file(s) changed.");
        return 0;
    }

    private Task ScanAsync(string path, SemanticModel model, SyntaxNode syntaxRoot, bool excludedFile, bool refsOnlyFile)
    {
        foreach (var token in syntaxRoot.DescendantTokens(descendIntoTrivia: true))
        {
            if (!token.IsKind(SyntaxKind.IdentifierToken) || !(Matches(token.ValueText) || _explicitNames.Contains(token.ValueText)))
                continue;
            var symbol = Resolve(model, token);
            if (symbol is null)
            {
                if (!excludedFile && Matches(token.ValueText) && !token.Parent!.IsPartOfStructuredTrivia())
                    _problems.Add($"unresolved: {Where(path, token)}: {token.ValueText}");
                if (!excludedFile && !refsOnlyFile && comments && Matches(token.ValueText) && token.Parent!.IsPartOfStructuredTrivia())
                    Edit(path, token.Span, Substitute(token.ValueText));
                continue;
            }
            var newName = NewName(symbol);
            if (newName is null)
                continue;
            if (excludedFile)
            {
                _problems.Add($"excluded file refers to a renamed symbol: {Where(path, token)}: {token.ValueText}");
                continue;
            }
            var replacement = TokenReplacement(symbol, token.ValueText, newName);
            if (replacement is null)
            {
                _problems.Add($"cannot rename token: {Where(path, token)}: {token.ValueText} ({symbol.Name} -> {newName})");
                continue;
            }
            if (symbol is ILocalSymbol or IParameterSymbol or IRangeVariableSymbol)
                _localRenames++;
            else
                _renamed[Id(symbol)] = newName;

            if (token.Parent is IdentifierNameSyntax name
                && name.Ancestors().OfType<AnonymousObjectMemberDeclaratorSyntax>().FirstOrDefault() is { } declarator
                && Syntax.IsInferredFrom(declarator, name.Span))
            {
                Edit(path, new TextSpan(declarator.Expression.SpanStart, 0), $"{token.ValueText} = ");
                Console.WriteLine($"  named: {Where(path, token)}: {declarator}");
            }
            Edit(path, token.Span, replacement);
        }

        if (comments && !excludedFile && !refsOnlyFile)
        {
            foreach (var trivia in syntaxRoot.DescendantTrivia(descendIntoTrivia: true))
            {
                if (trivia.IsKind(SyntaxKind.SingleLineCommentTrivia) || trivia.IsKind(SyntaxKind.MultiLineCommentTrivia))
                    EditText(path, trivia.Span, trivia.ToString());
            }
            foreach (var token in syntaxRoot.DescendantTokens(descendIntoTrivia: true))
            {
                if (token.IsKind(SyntaxKind.XmlTextLiteralToken))
                    EditText(path, token.Span, token.Text);
            }
        }
        return Task.CompletedTask;
    }

    private void EditText(string path, TextSpan span, string text)
    {
        var updated = SubstituteComment(text);
        if (updated != text)
            Edit(path, span, updated);
    }

    private void Edit(string path, TextSpan span, string text)
    {
        if (!_edits.TryGetValue(path, out var list))
            _edits[path] = list = [];
        list.Add((span, text));
    }

    private static ISymbol? Resolve(SemanticModel model, SyntaxToken token)
    {
        var parent = token.Parent!;
        ISymbol? symbol = null;
        if (parent is SimpleNameSyntax simple && simple.Identifier == token)
        {
            var info = model.GetSymbolInfo(simple);
            symbol = info.Symbol ?? info.CandidateSymbols.FirstOrDefault();
            if (symbol is null && simple.Parent is NameEqualsSyntax { Parent: AnonymousObjectMemberDeclaratorSyntax member })
                symbol = model.GetDeclaredSymbol(member);
            if (symbol is null && simple.FirstAncestorOrSelf<CrefSyntax>() is { } cref)
            {
                var crefInfo = model.GetSymbolInfo(cref);
                symbol = crefInfo.Symbol ?? crefInfo.CandidateSymbols.FirstOrDefault();
            }
        }
        else
        {
            symbol = model.GetDeclaredSymbol(parent);
        }
        return symbol is null ? null : Normalize(symbol);
    }

    private static ISymbol Normalize(ISymbol symbol)
    {
        if (symbol is IMethodSymbol { MethodKind: MethodKind.Constructor or MethodKind.StaticConstructor or MethodKind.Destructor } ctor)
            return ctor.ContainingType.OriginalDefinition;
        if (symbol is IMethodSymbol { ReducedFrom: { } reduced })
            symbol = reduced;
        if (symbol is IAliasSymbol || symbol is IFieldSymbol { ContainingType.IsTupleType: true })
            return symbol;
        return symbol.OriginalDefinition;
    }

    private string? NewName(ISymbol symbol)
    {
        var id = DocumentationCommentId.CreateDeclarationId(symbol);
        if (id is not null && _explicit.TryGetValue(id, out var explicitName))
        {
            _foundExplicit.Add(id);
            return explicitName;
        }
        if (!Matches(symbol.Name) || (id is not null && keeps.Contains(id)))
            return null;
        // A partial type may have a generated part (a [GeneratedRegex] partial); the generator follows the rename.
        var locations = symbol.Locations.Where(l => l.IsInSource && !IsGenerated(l.SourceTree!.FilePath)).ToList();
        if (locations.Count == 0 || locations.Any(l => isExcluded(l.SourceTree!.FilePath) || isRefsOnly(l.SourceTree!.FilePath)))
            return null;
        if (symbol.ContainingType is { IsAnonymousType: true })
            return null;
        if (symbol is IParameterSymbol parameter && IsBoundByName(parameter))
            return null;
        return Substitute(symbol.Name);
    }

    // Parameters whose names are part of the HTTP contract (route and query binding), and record
    // positional parameters whose property is kept.
    private bool IsBoundByName(IParameterSymbol parameter)
    {
        if (parameter.GetAttributes().Any(a => a.AttributeClass?.Name is "FromQueryAttribute" or "FromRouteAttribute" or "FromHeaderAttribute" or "FromFormAttribute"))
            return true;
        if (parameter.ContainingSymbol is not IMethodSymbol method)
            return false;
        if (method.MethodKind == MethodKind.Ordinary && method.DeclaredAccessibility == Accessibility.Public && IsController(method.ContainingType))
            return true;
        if (method.MethodKind == MethodKind.Constructor && method.ContainingType.IsRecord
            && method.ContainingType.GetMembers(parameter.Name).OfType<IPropertySymbol>().FirstOrDefault() is { } property)
            return NewName(property) is null;
        return false;
    }

    private static bool IsController(INamedTypeSymbol? type)
    {
        for (; type is not null; type = type.BaseType)
            if (type.Name == "ControllerBase" && type.ContainingNamespace.ToDisplayString() == "Microsoft.AspNetCore.Mvc")
                return true;
        return false;
    }

    private static string? TokenReplacement(ISymbol symbol, string tokenText, string newName)
    {
        if (tokenText == symbol.Name)
            return newName;
        if (symbol is INamedTypeSymbol && symbol.Name == tokenText + "Attribute" && newName.EndsWith("Attribute", StringComparison.Ordinal))
            return newName[..^"Attribute".Length];
        return null;
    }

    private bool Matches(string name) => rules.Any(r => Variants(r).Any(v => name.Contains(v.From, StringComparison.Ordinal)));

    private string Substitute(string text)
    {
        foreach (var rule in rules)
            foreach (var (from, to) in Variants(rule))
                text = text.Replace(from, to, StringComparison.Ordinal);
        return text;
    }

    private string SubstituteComment(string text)
    {
        var held = new List<string>();
        foreach (var word in keepWords.OrderByDescending(w => w.Length))
        {
            while (text.Contains(word, StringComparison.Ordinal))
            {
                text = ReplaceFirst(text, word, $"\u0001{held.Count}\u0002");
                held.Add(word);
            }
        }
        foreach (var (from, to) in words)
            text = text.Replace(from, to, StringComparison.Ordinal);
        text = Substitute(text);
        for (var i = 0; i < held.Count; i++)
            text = text.Replace($"\u0001{i}\u0002", held[i], StringComparison.Ordinal);
        return text;
    }

    private static string ReplaceFirst(string text, string word, string with)
    {
        var at = text.IndexOf(word, StringComparison.Ordinal);
        return text[..at] + with + text[(at + word.Length)..];
    }

    private static IEnumerable<(string From, string To)> Variants((string From, string To) rule)
    {
        yield return (rule.From.ToUpperInvariant(), rule.To.ToUpperInvariant());
        yield return (rule.From, rule.To);
        yield return (char.ToLowerInvariant(rule.From[0]) + rule.From[1..], char.ToLowerInvariant(rule.To[0]) + rule.To[1..]);
    }

    private static bool IsGenerated(string path)
    {
        var p = path.Replace('\\', '/');
        return p.Contains("/obj/", StringComparison.OrdinalIgnoreCase) || p.Contains("/bin/", StringComparison.OrdinalIgnoreCase);
    }

    private static string Id(ISymbol symbol) =>
        DocumentationCommentId.CreateDeclarationId(symbol) ?? $"{symbol.Kind}:{symbol.ContainingSymbol?.ToDisplayString()}.{symbol.Name}";

    private string Where(string path, SyntaxToken token) =>
        $"{Path.GetRelativePath(root, path)}:{token.GetLocation().GetLineSpan().StartLinePosition.Line + 1}";

    private static void WriteKeepingBom(string path, string text)
    {
        var bytes = File.ReadAllBytes(path);
        var bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
        File.WriteAllText(path, text, new UTF8Encoding(bom));
    }
}
