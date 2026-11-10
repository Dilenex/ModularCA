using System.Reflection;
using ModularCA.Tests.DisasterRecovery;
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: Xunit.TestFramework("ModularCA.Tests.TestUtils.PhasedTestFramework", "ModularCA.Tests")]

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// xUnit's own framework with one change to the order test collections run in. The parallel
/// collections run in three phases, each starting when the one before has finished: everything
/// that is in no later phase; then the PostgreSQL lanes (<see cref="PostgresLane"/>), beside
/// each other; then the two restore drills (<see cref="RestoreDrillCollection"/>), beside each
/// other. Collections with parallelization off still run last, one at a time, as xUnit runs
/// them.
/// </summary>
/// <remarks>
/// <para>
/// xUnit 2 has two phases: every parallel collection at once, then every non-parallel collection
/// in turn. The PostgreSQL tests fit neither. Beside the rest of the suite, which starts
/// hundreds of processes and writes thousands of files, the test server's checkpoints ran to a
/// minute and its connections missed the product's 15 s connect timeout; one after another,
/// they are twenty minutes of the run. So they get a phase of their own: the six lanes at once,
/// with nothing else running. The restore drills, which run whole nodes against the same
/// server, get the phase after that for the same reason.
/// </para>
/// <para>
/// Nothing else is changed: discovery, the parallel thread limit, fixtures, ordering inside a
/// collection and reporting are all xUnit's. A phase the filter left empty takes no time.
/// </para>
/// </remarks>
public sealed class PhasedTestFramework(IMessageSink messageSink) : XunitTestFramework(messageSink)
{
    /// <summary>How many phases the parallel collections run in.</summary>
    private const int Phases = 3;

    /// <summary>The phase a parallel collection runs in, from 0.</summary>
    private static int PhaseOf(ITestCollection collection)
    {
        if (collection.DisplayName.StartsWith(RestoreDrillCollection.Prefix, StringComparison.Ordinal))
            return 2;
        return PostgresLane.Is(collection) ? 1 : 0;
    }

    /// <inheritdoc />
    protected override ITestFrameworkExecutor CreateExecutor(AssemblyName assemblyName)
        => new PhasedExecutor(assemblyName, SourceInformationProvider, DiagnosticMessageSink);

    /// <summary>xUnit's executor, running the assembly through <see cref="PhasedAssemblyRunner"/>.</summary>
    private sealed class PhasedExecutor(AssemblyName assemblyName, ISourceInformationProvider sourceInformationProvider, IMessageSink diagnosticMessageSink)
        : XunitTestFrameworkExecutor(assemblyName, sourceInformationProvider, diagnosticMessageSink)
    {
        /// <inheritdoc />
        protected override async void RunTestCases(IEnumerable<IXunitTestCase> testCases, IMessageSink executionMessageSink, ITestFrameworkExecutionOptions executionOptions)
        {
            using var runner = new PhasedAssemblyRunner(TestAssembly, testCases, DiagnosticMessageSink, executionMessageSink, executionOptions);
            await runner.RunAsync();
        }
    }

    /// <summary>
    /// xUnit's assembly runner, holding each parallel collection back until the collections of
    /// the phases before its own have finished.
    /// </summary>
    private sealed class PhasedAssemblyRunner(
        ITestAssembly testAssembly, IEnumerable<IXunitTestCase> testCases, IMessageSink diagnosticMessageSink,
        IMessageSink executionMessageSink, ITestFrameworkExecutionOptions executionOptions)
        : XunitTestAssemblyRunner(testAssembly, testCases, diagnosticMessageSink, executionMessageSink, executionOptions)
    {
        private readonly object _lock = new();
        private readonly int[] _left = new int[Phases];
        private readonly TaskCompletionSource[] _done =
            Enumerable.Range(0, Phases).Select(_ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).ToArray();

        /// <inheritdoc />
        protected override Task<RunSummary> RunTestCollectionsAsync(IMessageBus messageBus, CancellationTokenSource cancellationTokenSource)
        {
            foreach (var collection in TestCases.Select(c => c.TestMethod.TestClass.TestCollection).DistinctBy(c => c.UniqueID))
            {
                if (!ParallelizationDisabled(collection))
                    _left[PhaseOf(collection)]++;
            }
            // With parallelization off xUnit runs the collections in turn, in its own order, and
            // a collection that waited for an earlier phase would wait for ever.
            var unphased = ExecutionOptions.DisableParallelizationOrDefault();
            for (var phase = 0; phase < Phases; phase++)
            {
                if (unphased || _left[phase] == 0)
                    _done[phase].TrySetResult();
            }
            return base.RunTestCollectionsAsync(messageBus, cancellationTokenSource);
        }

        /// <inheritdoc />
        protected override async Task<RunSummary> RunTestCollectionAsync(
            IMessageBus messageBus, ITestCollection testCollection, IEnumerable<IXunitTestCase> testCases, CancellationTokenSource cancellationTokenSource)
        {
            if (ParallelizationDisabled(testCollection))
                return await base.RunTestCollectionAsync(messageBus, testCollection, testCases, cancellationTokenSource);

            var phase = PhaseOf(testCollection);
            // Waited for here, before xUnit counts the collection as running, so a waiting
            // collection takes none of the parallel slots the earlier phases need.
            for (var earlier = 0; earlier < phase; earlier++)
                await _done[earlier].Task;
            try
            {
                return await base.RunTestCollectionAsync(messageBus, testCollection, testCases, cancellationTokenSource);
            }
            finally
            {
                lock (_lock)
                {
                    if (--_left[phase] == 0)
                        _done[phase].TrySetResult();
                }
            }
        }

        /// <summary>Whether the collection's definition turns parallelization off, read as xUnit reads it.</summary>
        private static bool ParallelizationDisabled(ITestCollection collection)
            => collection.CollectionDefinition?
                .GetCustomAttributes(typeof(Xunit.CollectionDefinitionAttribute))
                .SingleOrDefault()?
                .GetNamedArgument<bool>(nameof(Xunit.CollectionDefinitionAttribute.DisableParallelization)) == true;
    }
}
