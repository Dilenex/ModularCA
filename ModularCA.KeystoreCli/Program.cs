using ModularCA.Keystore;

// Break-glass keystore unlocker.
//
// Split out of ModularCA.Keystore, which had carried both this entry point and the library the
// rest of the system references. That dual role made the library an OutputType=Exe, which emits
// an apphost plus its own deps.json/runtimeconfig.json — and a RID-targeted publish of
// ModularCA.API then resolved it twice, once RID-less and once for the target RID, so
// `dotnet publish -r linux-x64` failed with NETSDK1152 and (before a partial workaround) dropped
// a Windows .exe into a Linux dist.
//
// The tool is deliberately a separate executable rather than a subcommand of the API: it exists
// for the case where the application will not start, and it must not depend on the application's
// hosting, configuration or DI to run.
Console.WriteLine("ModularCA.Keystore unlocker starting...");
Unlocker.Run(args);
