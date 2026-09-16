# Third-party notices

ModularCA is licensed under AGPL-3.0. It is distributed as a self-contained binary,
which means the components below travel inside it, and their licences require their
copyright notices to travel with them. This file is that disclosure.

**Generated** by `scripts/generate-third-party-notices.mjs` from the resolved dependency
graphs. Do not edit by hand — regenerate it, or the disclosure stops describing the
binary it ships beside, which is worse than having none.

Listed here is what is **distributed**: the runtime .NET graph and the npm packages that
end up inside a browser bundle. Build tooling never leaves the build machine and creates
no redistribution obligation; it is summarised at the end for completeness, not necessity.

## Licences in this distribution

| Licence | Components |
| --- | ---: |
| MIT | 69 |
| Apache-2.0 | 17 |
| ISC | 1 |
| unstated | 1 |
| 0BSD | 1 |

## Requires manual verification

These ship no licence expression and no licence file. Their terms must be
confirmed at source before the next release is distributed.

- **Serilog.Sinks.Network 3.0.0** — https://github.com/serilog-contrib/Serilog.Sinks.Network

## .NET runtime components (78)

| Package | Version | Licence | Copyright |
| --- | --- | --- | --- |
| [BouncyCastle.Cryptography](https://www.bouncycastle.org/stable/nuget/csharp/website) | 2.6.2 | MIT | Copyright © Legion of the Bouncy Castle Inc. 2000-2025 |
| [DnsClient](http://dnsclient.michaco.net/) | 1.8.0 | Apache-2.0 | Copyright (c) 2024 Michael Conrad |
| [Fido2.AspNet](https://github.com/passwordless-lib/fido2-net-lib) | 4.0.1 | MIT | — |
| [Fido2.Models](https://github.com/passwordless-lib/fido2-net-lib) | 4.0.1 | MIT | — |
| [Fido2](https://github.com/passwordless-lib/fido2-net-lib) | 4.0.1 | MIT | — |
| [FluentValidation.DependencyInjectionExtensions](https://fluentvalidation.net/) | 12.1.1 | Apache-2.0 | Copyright (c) Jeremy Skinner, .NET Foundation, and contributors 2008-2025 |
| [FluentValidation](https://fluentvalidation.net/) | 12.1.1 | Apache-2.0 | Copyright (c) Jeremy Skinner, .NET Foundation, and contributors 2008-2025 |
| [Humanizer.Core](https://github.com/Humanizr/Humanizer) | 2.14.1 | MIT | Copyright (c) .NET Foundation and Contributors |
| [Kerberos.NET](https://github.com/dotnet/Kerberos.NET) | 4.6.168 | MIT | Copyright (c) .NET Foundation and Contributors |
| [libsodium](https://libsodium.org/) | 1.0.20.1 | ISC | © 2024 Frank Denis |
| [MailKit](http://www.mimekit.net/) | 4.16.0 | MIT | .NET Foundation and Contributors |
| [Microsoft.AspNetCore.Authentication.JwtBearer](https://asp.net/) | 10.0.5 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.AspNetCore.DataProtection.StackExchangeRedis](https://asp.net/) | 9.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Bcl.AsyncInterfaces](https://dot.net/) | 7.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Bcl.Memory](https://dot.net/) | 9.0.14 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Build.Framework](http://go.microsoft.com/fwlink/?LinkId=624683) | 17.8.43 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Build.Locator](https://github.com/microsoft/MSBuildLocator) | 1.7.8 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.Analyzers](https://github.com/dotnet/roslyn-analyzers) | 3.3.4 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.Common](https://github.com/dotnet/roslyn) | 4.8.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.CSharp.Workspaces](https://github.com/dotnet/roslyn) | 4.8.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.CSharp](https://github.com/dotnet/roslyn) | 4.8.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.Workspaces.Common](https://github.com/dotnet/roslyn) | 4.8.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.Workspaces.MSBuild](https://github.com/dotnet/roslyn) | 4.8.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore.Abstractions](https://docs.microsoft.com/ef/core/) | 9.0.14 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore.Analyzers](https://docs.microsoft.com/ef/core/) | 9.0.14 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore.Design](https://docs.microsoft.com/ef/core/) | 9.0.14 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore.Relational](https://docs.microsoft.com/ef/core/) | 9.0.14 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore](https://docs.microsoft.com/ef/core/) | 9.0.14 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Extensions.ApiDescription.Server](https://asp.net/) | 10.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Extensions.Caching.StackExchangeRedis](https://asp.net/) | 9.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Extensions.DependencyModel](https://dot.net/) | 10.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Extensions.Hosting.Systemd](https://dot.net/) | 10.0.5 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Abstractions](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.17.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.JsonWebTokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.17.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Logging](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.17.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Protocols.OpenIdConnect](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.0.1 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Protocols](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.0.1 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Tokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.17.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.OpenApi](https://github.com/Microsoft/OpenAPI.NET) | 2.7.5 | MIT | © Microsoft Corporation. All rights reserved. |
| [MimeKit](https://www.mimekit.net/) | 4.16.0 | MIT | .NET Foundation and Contributors |
| [Mono.TextTemplating](https://github.com/mono/t4) | 3.0.0 | MIT | — |
| [MySqlConnector](https://mysqlconnector.net/) | 2.5.0 | MIT | Copyright 2016–2025 Bradley Grainger |
| [NCrontab.Signed](https://github.com/atifaziz/NCrontab) | 3.4.0 | Apache-2.0 | Copyright © 2008 Atif Aziz. All rights reserved. Portions Copyright © 2001 The OpenSymphony Group. All rights reserved. Portions Copyright © 2023 Microsoft Corp. All rights reserved. |
| [NSec.Cryptography](https://nsec.rocks/) | 25.4.0 | MIT | © 2025 Klaus Hartke |
| [Pipelines.Sockets.Unofficial](https://github.com/mgravell/Pipelines.Sockets.Unofficial) | 2.2.8 | MIT | Marc Gravell 2018 |
| [Pkcs11Interop](https://www.pkcs11interop.net/) | 5.3.0 | Apache-2.0 | Copyright (c) 2012-2025 The Pkcs11Interop Project |
| [Pomelo.EntityFrameworkCore.MySql](https://github.com/PomeloFoundation/Pomelo.EntityFrameworkCore.MySql) | 9.0.0 | MIT | Copyright 2025 © Pomelo Foundation |
| [prometheus-net.AspNetCore](https://github.com/prometheus-net/prometheus-net) | 8.2.1 | MIT | Copyright © prometheus-net developers |
| [prometheus-net](https://github.com/prometheus-net/prometheus-net) | 8.2.1 | MIT | Copyright © prometheus-net developers |
| [Serilog.AspNetCore](https://github.com/serilog/serilog-aspnetcore) | 10.0.0 | Apache-2.0 | — |
| [Serilog.Extensions.Hosting](https://github.com/serilog/serilog-extensions-hosting) | 10.0.0 | Apache-2.0 | — |
| [Serilog.Extensions.Logging](https://github.com/serilog/serilog-extensions-logging) | 10.0.0 | Apache-2.0 | — |
| [Serilog.Formatting.Compact](https://github.com/serilog/serilog-formatting-compact) | 3.0.0 | Apache-2.0 | — |
| [Serilog.Settings.Configuration](https://github.com/serilog/serilog-settings-configuration) | 10.0.0 | Apache-2.0 | — |
| [Serilog.Sinks.Console](https://github.com/serilog/serilog-sinks-console) | 6.1.1 | Apache-2.0 | — |
| [Serilog.Sinks.Debug](https://github.com/serilog/serilog-sinks-debug) | 3.0.0 | Apache-2.0 | — |
| [Serilog.Sinks.EventLog](https://serilog.net/) | 4.0.0 | Apache-2.0 | Copyright © Serilog Contributors |
| [Serilog.Sinks.File](https://github.com/serilog/serilog-sinks-file) | 7.0.0 | Apache-2.0 | — |
| [Serilog.Sinks.Network](https://github.com/serilog-contrib/Serilog.Sinks.Network) | 3.0.0 | — | — |
| [Serilog.Sinks.PeriodicBatching](https://github.com/serilog/serilog-sinks-periodicbatching) | 5.0.0 | Apache-2.0 | — |
| [Serilog.Sinks.SyslogMessages](https://github.com/IonxSolutions/serilog-sinks-syslog) | 4.1.0 | Apache-2.0 | Copyright © Ionx Solutions 2018 |
| [Serilog](https://serilog.net/) | 4.3.0 | Apache-2.0 | Copyright © Serilog Contributors |
| [StackExchange.Redis](https://stackexchange.github.io/StackExchange.Redis/) | 2.7.27 | MIT | 2014 - 2024 Stack Exchange, Inc. |
| [Swashbuckle.AspNetCore.Swagger](https://github.com/domaindrivendev/Swashbuckle.AspNetCore) | 10.1.7 | MIT | Copyright (c) 2016-2026 Richard Morris |
| [Swashbuckle.AspNetCore.SwaggerGen](https://github.com/domaindrivendev/Swashbuckle.AspNetCore) | 10.1.7 | MIT | Copyright (c) 2016-2026 Richard Morris |
| [Swashbuckle.AspNetCore.SwaggerUI](https://github.com/domaindrivendev/Swashbuckle.AspNetCore) | 10.1.7 | MIT | Copyright (c) 2016-2026 Richard Morris |
| [Swashbuckle.AspNetCore](https://github.com/domaindrivendev/Swashbuckle.AspNetCore) | 10.1.7 | MIT | — |
| [System.CodeDom](https://dot.net/) | 6.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.AttributedModel](https://dot.net/) | 7.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.Convention](https://dot.net/) | 7.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.Hosting](https://dot.net/) | 7.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.Runtime](https://dot.net/) | 7.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.TypedParts](https://dot.net/) | 7.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition](https://dot.net/) | 7.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.DirectoryServices.Protocols](https://dot.net/) | 10.0.5 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.IdentityModel.Tokens.Jwt](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.17.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Security.Cryptography.Pkcs](https://dot.net/) | 10.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [YamlDotNet](https://github.com/aaubry/YamlDotNet/wiki) | 16.3.0 | MIT | Copyright (c) Antoine Aubry and contributors |

### NOTICE files

Apache-2.0 section 4(d) requires these to be carried with any distribution.

#### NSec.Cryptography 25.4.0

```
License Notice for libsodium
----------------------------

This software is based on and contains code derived from libsodium, which is
available under the ISC license.

Copyright (c) 2013-2025 Frank Denis

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


License Notice for RFC 6234
---------------------------

This software contains code derived from the sample code in RFC 6234, which is
available under a Simplified BSD License.

Copyright (c) 2011 IETF Trust and the persons identified as authors of the code.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of Internet Society, IETF or IETF Trust, nor the names of
      specific contributors, may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


License Notice for .NET Runtime
-------------------------------

This software contains code derived from the .NET Runtime, which are available
under the MIT license.

Copyright (c) .NET Foundation and Contributors
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


License Notice for Hex and Base64 Implementation
------------------------------------------------

This software contains code derived from Steve Thomas's Hex and Base64
implementation, which is available under the MIT license.

Copyright (c) 2014 Steve Thomas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

#### Pkcs11Interop 5.3.0

```
This product includes software developed at
The Pkcs11Interop Project (http://www.pkcs11interop.net).
```

## Browser runtime components (11)

Bundled into the admin, user, public, setup and docs interfaces.

| Package | Version | Licence | Source |
| --- | --- | --- | --- |
| @napi-rs/wasm-runtime | 1.1.3 | MIT | https://github.com/napi-rs/napi-rs |
| @tybys/wasm-util | 0.10.1 | MIT | https://github.com/toyobayashi/wasm-util |
| cookie | 1.1.1 | MIT | jshttp/cookie |
| qrcode-generator | 2.0.4 | MIT | https://github.com/kazuhikoarase/qrcode-generator |
| react | 19.2.4 | MIT | https://github.com/facebook/react |
| react-dom | 19.2.4 | MIT | https://github.com/facebook/react |
| react-router | 7.18.2 | MIT | https://github.com/remix-run/react-router |
| react-router-dom | 7.18.2 | MIT | https://github.com/remix-run/react-router |
| scheduler | 0.27.0 | MIT | https://github.com/facebook/react |
| set-cookie-parser | 2.7.2 | MIT | nfriedly/set-cookie-parser |
| tslib | 2.8.1 | 0BSD | https://github.com/Microsoft/tslib |

## Build tooling (not distributed)

These produce the binary and are not part of it, so no redistribution obligation
attaches. Recorded because "what built this" is a fair question about a certificate
authority even where no licence compels the answer.

- **.NET SDK 10** and the C# compiler — MIT, Microsoft
- **Vite**, **Rolldown**, **TypeScript**, **Tailwind CSS**, **PostCSS**, **autoprefixer** — MIT
- **xunit**, **vitest** — Apache-2.0 and MIT respectively
- **nfpm** — MIT, used to build the Debian package

The full build-time graph, with versions, is in the `package-lock.json` of each
interface and in `ModularCA.API/obj/project.assets.json` after a restore.

