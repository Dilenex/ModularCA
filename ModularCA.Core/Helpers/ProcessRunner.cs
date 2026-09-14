using System.Diagnostics;

namespace ModularCA.Core.Helpers;

/// <summary>
/// Runs external processes asynchronously with timeout support and captured output.
/// </summary>
public static class ProcessRunner
{
    /// <summary>
    /// Executes a command asynchronously, returning the exit code, stdout, and stderr.
    /// </summary>
    /// <summary>
    /// Runs a process with a single pre-formatted argument string.
    /// </summary>
    /// <remarks>
    /// The string is re-tokenised by the runtime on whitespace and quotes, so any value that
    /// reaches it from outside the process must already be quoted. Prefer the
    /// <see cref="RunAsync(string, IReadOnlyList{string}, int)"/> overload for anything that
    /// carries caller-supplied text: it passes each argument as exactly one token.
    /// </remarks>
    public static async Task<(int ExitCode, string Stdout, string Stderr)> RunAsync(
        string command, string arguments, int timeoutMs = 30000)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = command,
            Arguments = arguments,
        };
        return await RunAsync(startInfo, timeoutMs);
    }

    /// <summary>
    /// Runs a process with each argument passed as exactly one token, whatever it contains.
    /// </summary>
    /// <remarks>
    /// This is the overload for arguments that carry caller-supplied text. With the string
    /// overload, an SSH <c>force-command</c> value of <c>x -O clear</c> became three tokens on
    /// the <c>ssh-keygen</c> command line, and the caller had appended a flag of their choosing.
    /// <see cref="ProcessStartInfo.ArgumentList"/> hands each entry to the child as one argv
    /// element, so a space, a quote or a leading dash inside a value stays inside that value.
    /// </remarks>
    public static async Task<(int ExitCode, string Stdout, string Stderr)> RunAsync(
        string command, IReadOnlyList<string> arguments, int timeoutMs = 30000)
    {
        var startInfo = new ProcessStartInfo { FileName = command };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);
        return await RunAsync(startInfo, timeoutMs);
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunAsync(
        ProcessStartInfo startInfo, int timeoutMs)
    {
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;

        using var process = new Process { StartInfo = startInfo };

        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        var completed = await Task.Run(() => process.WaitForExit(timeoutMs));
        if (!completed)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"Process '{startInfo.FileName}' timed out after {timeoutMs}ms");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        return (process.ExitCode, stdout, stderr);
    }
}
