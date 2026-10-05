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
| MIT | 68 |
| Apache-2.0 | 24 |
| PostgreSQL | 2 |
| OFL-1.1 | 2 |
| BSD-3-Clause | 1 |
| ISC | 1 |
| unstated | 1 |

## Requires manual verification

These ship no licence expression and no licence file. Their terms must be
confirmed at source before the next release is distributed.

- **Serilog.Sinks.Network 3.0.0** — https://github.com/serilog-contrib/Serilog.Sinks.Network

## .NET runtime components (89)

| Package | Version | Licence | Copyright |
| --- | --- | --- | --- |
| [BouncyCastle.Cryptography](https://www.bouncycastle.org/stable/nuget/csharp/website) | 2.7.0 | MIT | Copyright © Legion of the Bouncy Castle Inc. 2000-2026 |
| [DnsClient](http://dnsclient.michaco.net/) | 1.8.0 | Apache-2.0 | Copyright (c) 2024 Michael Conrad |
| [Fido2.AspNet](https://github.com/passwordless-lib/fido2-net-lib) | 4.0.1 | MIT | — |
| [Fido2.Models](https://github.com/passwordless-lib/fido2-net-lib) | 4.0.1 | MIT | — |
| [Fido2](https://github.com/passwordless-lib/fido2-net-lib) | 4.0.1 | MIT | — |
| [FluentValidation.DependencyInjectionExtensions](https://fluentvalidation.net/) | 12.1.1 | Apache-2.0 | Copyright (c) Jeremy Skinner, .NET Foundation, and contributors 2008-2025 |
| [FluentValidation](https://fluentvalidation.net/) | 12.1.1 | Apache-2.0 | Copyright (c) Jeremy Skinner, .NET Foundation, and contributors 2008-2025 |
| [Google.Protobuf](https://github.com/protocolbuffers/protobuf) | 3.36.1 | BSD-3-Clause | Copyright 2015, Google Inc. |
| [Grpc.AspNetCore.Server.ClientFactory](https://github.com/grpc/grpc-dotnet) | 2.83.0 | Apache-2.0 | Copyright 2019 The gRPC Authors |
| [Grpc.AspNetCore.Server](https://github.com/grpc/grpc-dotnet) | 2.83.0 | Apache-2.0 | Copyright 2019 The gRPC Authors |
| [Grpc.AspNetCore](https://github.com/grpc/grpc-dotnet) | 2.83.0 | Apache-2.0 | Copyright 2019 The gRPC Authors |
| [Grpc.Core.Api](https://github.com/grpc/grpc-dotnet) | 2.83.0 | Apache-2.0 | Copyright 2019 The gRPC Authors |
| [Grpc.Net.Client](https://github.com/grpc/grpc-dotnet) | 2.83.0 | Apache-2.0 | Copyright 2019 The gRPC Authors |
| [Grpc.Net.ClientFactory](https://github.com/grpc/grpc-dotnet) | 2.83.0 | Apache-2.0 | Copyright 2019 The gRPC Authors |
| [Grpc.Net.Common](https://github.com/grpc/grpc-dotnet) | 2.83.0 | Apache-2.0 | Copyright 2019 The gRPC Authors |
| [Humanizer.Core](https://github.com/Humanizr/Humanizer) | 2.14.1 | MIT | Copyright (c) .NET Foundation and Contributors |
| [Kerberos.NET](https://github.com/dotnet/Kerberos.NET) | 4.6.168 | MIT | Copyright (c) .NET Foundation and Contributors |
| [libsodium](https://libsodium.org/) | 1.0.20.1 | ISC | © 2024 Frank Denis |
| [MailKit](http://www.mimekit.net/) | 4.16.0 | MIT | .NET Foundation and Contributors |
| [Microsoft.AspNetCore.Authentication.JwtBearer](https://asp.net/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.AspNetCore.DataProtection.StackExchangeRedis](https://asp.net/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Bcl.Cryptography](https://dot.net/) | 10.0.2 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Bcl.Memory](https://dot.net/) | 9.0.14 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Build.Framework](http://go.microsoft.com/fwlink/?LinkId=624683) | 18.0.2 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.Analyzers](https://github.com/dotnet/roslyn-analyzers) | 3.11.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.Common](https://github.com/dotnet/roslyn) | 5.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.CSharp.Workspaces](https://github.com/dotnet/roslyn) | 5.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.CSharp](https://github.com/dotnet/roslyn) | 5.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.Workspaces.Common](https://github.com/dotnet/roslyn) | 5.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.CodeAnalysis.Workspaces.MSBuild](https://github.com/dotnet/roslyn) | 5.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore.Abstractions](https://docs.microsoft.com/ef/core/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore.Analyzers](https://docs.microsoft.com/ef/core/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore.Design](https://docs.microsoft.com/ef/core/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore.Relational](https://docs.microsoft.com/ef/core/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.EntityFrameworkCore](https://docs.microsoft.com/ef/core/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Extensions.ApiDescription.Server](https://asp.net/) | 10.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Extensions.Caching.StackExchangeRedis](https://asp.net/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Extensions.DependencyModel](https://dot.net/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.Extensions.Hosting.Systemd](https://dot.net/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Abstractions](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.22.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.JsonWebTokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.22.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Logging](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.22.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Protocols.OpenIdConnect](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.19.2 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Protocols](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.19.2 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.IdentityModel.Tokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.22.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.OpenApi](https://github.com/Microsoft/OpenAPI.NET) | 2.7.5 | MIT | © Microsoft Corporation. All rights reserved. |
| [Microsoft.VisualStudio.SolutionPersistence](https://github.com/microsoft/vs-solutionpersistence) | 1.0.52 | MIT | © Microsoft Corporation. All rights reserved. |
| [MimeKit](https://www.mimekit.net/) | 4.16.0 | MIT | .NET Foundation and Contributors |
| [Mono.TextTemplating](https://github.com/mono/t4) | 3.0.0 | MIT | — |
| [NCrontab.Signed](https://github.com/atifaziz/NCrontab) | 3.4.0 | Apache-2.0 | Copyright © 2008 Atif Aziz. All rights reserved. Portions Copyright © 2001 The OpenSymphony Group. All rights reserved. Portions Copyright © 2023 Microsoft Corp. All rights reserved. |
| [Newtonsoft.Json](https://www.newtonsoft.com/json) | 13.0.4 | MIT | Copyright © James Newton-King 2008 |
| [Npgsql.EntityFrameworkCore.PostgreSQL](https://github.com/npgsql/efcore.pg) | 10.0.3 | PostgreSQL | Copyright 2025 © The Npgsql Development Team |
| [Npgsql](https://github.com/npgsql/npgsql) | 10.0.3 | PostgreSQL | Copyright 2025 © The Npgsql Development Team |
| [NSec.Cryptography](https://nsec.rocks/) | 25.4.0 | MIT | © 2025 Klaus Hartke |
| [Pipelines.Sockets.Unofficial](https://github.com/mgravell/Pipelines.Sockets.Unofficial) | 2.2.8 | MIT | Marc Gravell 2018 |
| [Pkcs11Interop](https://www.pkcs11interop.net/) | 5.3.0 | Apache-2.0 | Copyright (c) 2012-2025 The Pkcs11Interop Project |
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
| [Serilog](https://serilog.net/) | 4.4.0 | Apache-2.0 | Copyright © Serilog Contributors |
| [StackExchange.Redis](https://stackexchange.github.io/StackExchange.Redis/) | 2.7.27 | MIT | 2014 - 2024 Stack Exchange, Inc. |
| [Swashbuckle.AspNetCore.Swagger](https://github.com/domaindrivendev/Swashbuckle.AspNetCore) | 10.2.3 | MIT | Copyright (c) 2016-2026 Richard Morris |
| [Swashbuckle.AspNetCore.SwaggerGen](https://github.com/domaindrivendev/Swashbuckle.AspNetCore) | 10.2.3 | MIT | Copyright (c) 2016-2026 Richard Morris |
| [Swashbuckle.AspNetCore.SwaggerUI](https://github.com/domaindrivendev/Swashbuckle.AspNetCore) | 10.2.3 | MIT | Copyright (c) 2016-2026 Richard Morris |
| [Swashbuckle.AspNetCore](https://github.com/domaindrivendev/Swashbuckle.AspNetCore) | 10.2.3 | MIT | — |
| [System.CodeDom](https://dot.net/) | 6.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.AttributedModel](https://dot.net/) | 9.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.Convention](https://dot.net/) | 9.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.Hosting](https://dot.net/) | 9.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.Runtime](https://dot.net/) | 9.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition.TypedParts](https://dot.net/) | 9.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Composition](https://dot.net/) | 9.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.DirectoryServices.Protocols](https://dot.net/) | 10.0.12 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.IdentityModel.Tokens.Jwt](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet) | 8.22.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.IO.Hashing](https://dot.net/) | 8.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [System.Security.Cryptography.Pkcs](https://dot.net/) | 10.0.0 | MIT | © Microsoft Corporation. All rights reserved. |
| [YamlDotNet](https://github.com/aaubry/YamlDotNet/wiki) | 16.3.0 | MIT | Copyright (c) Antoine Aubry and contributors |
| [Yarp.ReverseProxy](https://github.com/dotnet/yarp) | 2.3.0 | MIT | © Microsoft Corporation. All rights reserved. |

### NOTICE files

Apache-2.0 section 4(d) requires these to be carried with any distribution.

#### Microsoft.VisualStudio.SolutionPersistence 1.0.52

```
NOTICES AND INFORMATION
Do Not Translate or Localize

This software incorporates material from third parties.
Microsoft makes certain open source code available at https://3rdpartysource.microsoft.com,
or you may send a check or money order for US $5.00, including the product name,
the open source component name, platform, and version number, to:

Source Code Compliance Team
Microsoft Corporation
One Microsoft Way
Redmond, WA 98052
USA

Notwithstanding any other terms, you may reverse engineer this software to the extent
required to debug changes to any libraries licensed under the GNU Lesser General Public License.

---------------------------------------------------------

xunit.runner.visualstudio 3.0.2 - Apache-2.0


Copyright (c) .NET Foundation
Copyright (c) Outercurve Foundation

Apache License

Version 2.0, January 2004

http://www.apache.org/licenses/ TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      

      "License" shall mean the terms and conditions for use, reproduction, and distribution as defined by Sections 1 through 9 of this document.

      

      "Licensor" shall mean the copyright owner or entity authorized by the copyright owner that is granting the License.

      

      "Legal Entity" shall mean the union of the acting entity and all other entities that control, are controlled by, or are under common control with that entity. For the purposes of this definition, "control" means (i) the power, direct or indirect, to cause the direction or management of such entity, whether by contract or otherwise, or (ii) ownership of fifty percent (50%) or more of the outstanding shares, or (iii) beneficial ownership of such entity.

      

      "You" (or "Your") shall mean an individual or Legal Entity exercising permissions granted by this License.

      

      "Source" form shall mean the preferred form for making modifications, including but not limited to software source code, documentation source, and configuration files.

      

      "Object" form shall mean any form resulting from mechanical transformation or translation of a Source form, including but not limited to compiled object code, generated documentation, and conversions to other media types.

      

      "Work" shall mean the work of authorship, whether in Source or Object form, made available under the License, as indicated by a copyright notice that is included in or attached to the work (an example is provided in the Appendix below).

      

      "Derivative Works" shall mean any work, whether in Source or Object form, that is based on (or derived from) the Work and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship. For the purposes of this License, Derivative Works shall not include works that remain separable from, or merely link (or bind by name) to the interfaces of, the Work and Derivative Works thereof.

      

      "Contribution" shall mean any work of authorship, including the original version of the Work and any modifications or additions to that Work or Derivative Works thereof, that is intentionally submitted to Licensor for inclusion in the Work by the copyright owner or by an individual or Legal Entity authorized to submit on behalf of the copyright owner. For the purposes of this definition, "submitted" means any form of electronic, verbal, or written communication sent to the Licensor or its representatives, including but not limited to communication on electronic mailing lists, source code control systems, and issue tracking systems that are managed by, or on behalf of, the Licensor for the purpose of discussing and improving the Work, but excluding communication that is conspicuously marked or otherwise designated in writing by the copyright owner as "Not a Contribution."

      

      "Contributor" shall mean Licensor and any individual or Legal Entity on behalf of whom a Contribution has been received by Licensor and subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare Derivative Works of, publicly display, publicly perform, sublicense, and distribute the Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable (except as stated in this section) patent license to make, have made, use, offer to sell, sell, import, and otherwise transfer the Work, where such license applies only to those patent claims licensable by such Contributor that are necessarily infringed by their Contribution(s) alone or by combination of their Contribution(s) with the Work to which such Contribution(s) was submitted. If You institute patent litigation against any entity (including a cross-claim or counterclaim in a lawsuit) alleging that the Work or a Contribution incorporated within the Work constitutes direct or contributory patent infringement, then any patent licenses granted to You under this License for that Work shall terminate as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the Work or Derivative Works thereof in any medium, with or without modifications, and in Source or Object form, provided that You meet the following conditions:

      (a) You must give any other recipients of the Work or Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works that You distribute, all copyright, patent, trademark, and attribution notices from the Source form of the Work, excluding those notices that do not pertain to any part of the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its distribution, then any Derivative Works that You distribute must include a readable copy of the attribution notices contained within such NOTICE file, excluding those notices that do not pertain to any part of the Derivative Works, in at least one of the following places: within a NOTICE text file distributed as part of the Derivative Works; within the Source form or documentation, if provided along with the Derivative Works; or, within a display generated by the Derivative Works, if and wherever such third-party notices normally appear. The contents of the NOTICE file are for informational purposes only and do not modify the License. You may add Your own attribution notices within Derivative Works that You distribute, alongside or as an addendum to the NOTICE text from the Work, provided that such additional attribution notices cannot be construed as modifying the License.

      You may add Your own copyright statement to Your modifications and may provide additional or different license terms and conditions for use, reproduction, or distribution of Your modifications, or for any such Derivative Works as a whole, provided Your use, reproduction, and distribution of the Work otherwise complies with the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise, any Contribution intentionally submitted for inclusion in the Work by You to the Licensor shall be under the terms and conditions of this License, without any additional terms or conditions. Notwithstanding the above, nothing herein shall supersede or modify the terms of any separate license agreement you may have executed with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade names, trademarks, service marks, or product names of the Licensor, except as required for reasonable and customary use in describing the origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or agreed to in writing, Licensor provides the Work (and each Contributor provides its Contributions) on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible for determining the appropriateness of using or redistributing the Work and assume any risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall any Contributor be liable to You for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this License or out of the use or inability to use the Work (including but not limited to damages for loss of goodwill, work stoppage, computer failure or malfunction, or any and all other commercial damages or losses), even if such Contributor has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing the Work or Derivative Works thereof, You may choose to offer, and charge a fee for, acceptance of support, warranty, indemnity, or other liability obligations and/or rights consistent with this License. However, in accepting such obligations, You may act only on Your own behalf and on Your sole responsibility, not on behalf of any other Contributor, and only if You agree to indemnify, defend, and hold each Contributor harmless for any liability incurred by, or claims asserted against, such Contributor by reason of your accepting any such warranty or additional liability. END OF TERMS AND CONDITIONS

APPENDIX: How to apply the Apache License to your work.

To apply the Apache License to your work, attach the following boilerplate notice, with the fields enclosed by brackets "[]" replaced with your own identifying information. (Don't include the brackets!) The text should be enclosed in the appropriate comment syntax for the file format. We also recommend that a file or class name and description of purpose be included on the same "printed page" as the copyright notice for easier identification within third-party archives.

Copyright [yyyy] [name of copyright owner]

Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.

You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software

distributed under the License is distributed on an "AS IS" BASIS,

WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the License for the specific language governing permissions and

limitations under the License.

---------------------------------------------------------

---------------------------------------------------------

CSharpIsNullAnalyzer 0.1.593 - MIT


(c) Andrew Arnott

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

IsExternalInit 1.0.3 - MIT



MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

Microsoft.CodeAnalysis.PublicApiAnalyzers 3.3.4 - MIT


(c) Microsoft Corporation
Copyright (c) .NET Foundation
Copyright (c) 2013 Scott Kirkland
Copyright (c) 2012-2014 Mehdi Khalili
Copyright (c) 2013-2014 Omar Khudeira (http://omar.io)

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

Microsoft.IO.Redist 6.0.1 - MIT


(c) Microsoft Corporation
Copyright (c) Andrew Arnott
Copyright 2019 LLVM Project
Copyright 2018 Daniel Lemire
Copyright (c) .NET Foundation
Copyright (c) 2011, Google Inc.
Copyright (c) 2020 Dan Shechter
(c) 1997-2005 Sean Eron Anderson
Copyright (c) 1998 Microsoft. To
Copyright (c) 2017 Yoshifumi Kawai
Copyright (c) 2005-2020 Rich Felker
Copyright (c) Microsoft Corporation
Copyright (c) 2007 James Newton-King
Copyright (c) 2012-2014, Yann Collet
Copyright (c) 1991-2020 Unicode, Inc.
Copyright (c) 2013-2017, Alfred Klomp
Copyright 2012 the V8 project authors
Copyright (c) 2011-2020 Microsoft Corp
Copyright (c) 2015-2017, Wojciech Mula
Copyright (c) 2005-2007, Nick Galbreath
Copyright (c) 2015 The Chromium Authors
Copyright (c) 2018 Alexander Chermyanin
Copyright (c) The Internet Society 1997
Portions (c) International Organization
Copyright (c) 2004-2006 Intel Corporation
Copyright (c) 2013-2017, Milosz Krajewski
Copyright (c) 2016-2017, Matthieu Darbois
Copyright (c) The Internet Society (2003)
Copyright (c) .NET Foundation Contributors
Copyright (c) .NET Foundation and Contributors
Copyright (c) 2019 Microsoft Corporation, Daan Leijen
Copyright (c) 2011 Novell, Inc (http://www.novell.com)
Copyright (c) 1995-2022 Jean-loup Gailly and Mark Adler
Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors
Copyright (c) 2014 Ryan Juckett http://www.ryanjuckett.com
Copyright (c) 1990- 1993, 1996 Open Software Foundation, Inc.
Copyright (c) YEAR W3C(r) (MIT, ERCIM, Keio, Beihang). Disclaimers
Copyright (c) 2015 THL A29 Limited, a Tencent company, and Milo Yip
Copyright 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018 The Regents of the University of California
Copyright (c) 1989 by Hewlett-Packard Company, Palo Alto, Ca. & Digital Equipment Corporation, Maynard, Mass
Copyright (c) 1989 by Hewlett-Packard Company, Palo Alto, Ca. & Digital Equipment Corporation, Maynard, Mass. To

The MIT License (MIT)

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


---------------------------------------------------------

---------------------------------------------------------

Microsoft.TestPlatform.ObjectModel 17.12.0 - MIT


(c) Microsoft Corporation

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

Microsoft.VisualStudioEng.MicroBuild.Core 1.0.0 - MIT


(c) Microsoft Corporation
Copyright (c) 2024 http://microsoft.com Microsoft

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

Nerdbank.GitVersioning 3.7.115 - MIT


Copyright 1995-2022 Mark Adler
Copyright James Newton-King 2008
Copyright LibGit2Sharp contributors
Copyright James Newton-King 2008 Json.NET
Copyright (c) .NET Foundation and Contributors
Copyright AssemblyCompany AssemblyConfiguration
Copyright 1995-2022 Jean-loup Gailly and Mark Adler

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

Newtonsoft.Json 13.0.1 - MIT


Copyright James Newton-King 2008
Copyright (c) 2007 James Newton-King
Copyright (c) James Newton-King 2008
Copyright James Newton-King 2008 Json.NET

The MIT License (MIT)

Copyright (c) 2007 James Newton-King

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


---------------------------------------------------------

---------------------------------------------------------

PolySharp 1.15.0 - MIT


Copyright (c) 2023 Sergio Pedri
Copyright (c) 2023 Sergio Pedri OriginalFilename PolySharp.SourceGenerators.dll

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

StyleCop.Analyzers.Unstable 1.2.0.556 - MIT


copyright company
PlaceholderCompany Copyright (c)
Copyright (c) 2015 Dennis Fischer
Copyright (c) 2017 Marcos Lopez C.
Copyright 2014 Giovanni Bassi and Elemar Jr
Copyright (c) Tunnel Vision Laboratories, LLC
Copyright (c) .NET Foundation and Contributors
Copyright Tunnel Vision Laboratories, LLC 2015
copyright tag should contain a non-empty company
Copyright 2015 Tunnel Vision Laboratories, LLC StyleCop DotNetAnalyzers Roslyn Diagnostic Analyzer

MIT License

Copyright (c) Tunnel Vision Laboratories, LLC

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


---------------------------------------------------------

---------------------------------------------------------

System.Buffers 4.5.1 - MIT


(c) Microsoft Corporation
Copyright (c) 2011, Google Inc.
(c) 1997-2005 Sean Eron Anderson
Copyright (c) 1991-2017 Unicode, Inc.
Copyright (c) 2015 The Chromium Authors
Portions (c) International Organization
Copyright (c) 2004-2006 Intel Corporation
Copyright (c) .NET Foundation Contributors
Copyright (c) .NET Foundation and Contributors
Copyright (c) 2011 Novell, Inc (http://www.novell.com)
Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler
Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors
Copyright (c) YEAR W3C(r) (MIT, ERCIM, Keio, Beihang). Disclaimers

The MIT License (MIT)

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


---------------------------------------------------------

---------------------------------------------------------

System.Buffers 4.6.0 - MIT


(c) Microsoft Corporation

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

System.Collections.Immutable 8.0.0 - MIT


Copyright (c) Six Labors
(c) Microsoft Corporation
Copyright (c) Andrew Arnott
Copyright 2019 LLVM Project
Copyright 2018 Daniel Lemire
Copyright (c) .NET Foundation
Copyright (c) 2011, Google Inc.
Copyright (c) 2020 Dan Shechter
(c) 1997-2005 Sean Eron Anderson
Copyright (c) 1998 Microsoft. To
Copyright (c) 2022, Wojciech Mula
Copyright (c) 2017 Yoshifumi Kawai
Copyright (c) 2022, Geoff Langdale
Copyright (c) 2005-2020 Rich Felker
Copyright (c) 2012-2021 Yann Collet
Copyright (c) Microsoft Corporation
Copyright (c) 2007 James Newton-King
Copyright (c) 1991-2022 Unicode, Inc.
Copyright (c) 2013-2017, Alfred Klomp
Copyright 2012 the V8 project authors
Copyright (c) 1999 Lucent Technologies
Copyright (c) 2008-2016, Wojciech Mula
Copyright (c) 2011-2020 Microsoft Corp
Copyright (c) 2015-2017, Wojciech Mula
Copyright (c) 2021 csFastFloat authors
Copyright (c) 2005-2007, Nick Galbreath
Copyright (c) 2015 The Chromium Authors
Copyright (c) 2018 Alexander Chermyanin
Copyright (c) The Internet Society 1997
Portions (c) International Organization
Copyright (c) 2004-2006 Intel Corporation
Copyright (c) 2011-2015 Intel Corporation
Copyright (c) 2013-2017, Milosz Krajewski
Copyright (c) 2016-2017, Matthieu Darbois
Copyright (c) The Internet Society (2003)
Copyright (c) .NET Foundation Contributors
Copyright (c) 2020 Mara Bos <m-ou.se@m-ou.se>
Copyright (c) .NET Foundation and Contributors
Copyright (c) 2012 - present, Victor Zverovich
Copyright (c) 2006 Jb Evain (jbevain@gmail.com)
Copyright (c) 2008-2020 Advanced Micro Devices, Inc.
Copyright (c) 2019 Microsoft Corporation, Daan Leijen
Copyright (c) 2011 Novell, Inc (http://www.novell.com)
Copyright (c) 1995-2022 Jean-loup Gailly and Mark Adler
Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors
Copyright (c) 2014 Ryan Juckett http://www.ryanjuckett.com
Copyright (c) 1990- 1993, 1996 Open Software Foundation, Inc.
Copyright (c) YEAR W3C(r) (MIT, ERCIM, Keio, Beihang). Disclaimers
Copyright (c) 2015 THL A29 Limited, a Tencent company, and Milo Yip
Copyright (c) 1980, 1986, 1993 The Regents of the University of California
Copyright 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018 The Regents of the University of California
Copyright (c) 1989 by Hewlett-Packard Company, Palo Alto, Ca. & Digital Equipment Corporation, Maynard, Mass

The MIT License (MIT)

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


---------------------------------------------------------

---------------------------------------------------------

System.Memory 4.5.5 - MIT


(c) 2022 GitHub, Inc.
(c) Microsoft Corporation
Copyright (c) 2011, Google Inc.
(c) 1997-2005 Sean Eron Anderson
Copyright (c) 1991-2017 Unicode, Inc.
Copyright (c) 2015 The Chromium Authors
Portions (c) International Organization
Copyright (c) 2004-2006 Intel Corporation
Copyright (c) .NET Foundation Contributors
Copyright (c) .NET Foundation and Contributors
Copyright (c) 2011 Novell, Inc (http://www.novell.com)
Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler
Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors
Copyright (c) YEAR W3C(r) (MIT, ERCIM, Keio, Beihang). Disclaimers

The MIT License (MIT)

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


---------------------------------------------------------

---------------------------------------------------------

System.Memory 4.6.0 - MIT


(c) Microsoft Corporation

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

System.Numerics.Vectors 4.5.0 - MIT


(c) 2023 GitHub, Inc.
(c) Microsoft Corporation
Copyright (c) .NET Foundation
Copyright (c) 2011, Google Inc.
(c) 1997-2005 Sean Eron Anderson
Copyright (c) 1991-2017 Unicode, Inc.
Copyright (c) 2015 The Chromium Authors
Portions (c) International Organization
Copyright (c) 2004-2006 Intel Corporation
Copyright (c) .NET Foundation Contributors
Copyright (c) .NET Foundation and Contributors
Copyright (c) 2011 Novell, Inc (http://www.novell.com)
Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler
Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors
Copyright (c) YEAR W3C(r) (MIT, ERCIM, Keio, Beihang). Disclaimers

The MIT License (MIT)

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


---------------------------------------------------------

---------------------------------------------------------

System.Numerics.Vectors 4.6.0 - MIT


(c) Microsoft Corporation

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

System.Reflection.Metadata 1.6.0 - MIT


(c) 2023 GitHub, Inc.
(c) Microsoft Corporation
Copyright (c) .NET Foundation
Copyright (c) 2011, Google Inc.
(c) 1997-2005 Sean Eron Anderson
Copyright (c) 1991-2017 Unicode, Inc.
Copyright (c) 2015 The Chromium Authors
Portions (c) International Organization
Copyright (c) 2004-2006 Intel Corporation
Copyright (c) .NET Foundation Contributors
Copyright (c) .NET Foundation and Contributors
Copyright (c) 2011 Novell, Inc (http://www.novell.com)
Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler
Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors
Copyright (c) YEAR W3C(r) (MIT, ERCIM, Keio, Beihang). Disclaimers

The MIT License (MIT)

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


---------------------------------------------------------

---------------------------------------------------------

System.Runtime.CompilerServices.Unsafe 4.5.3 - MIT


(c) Microsoft Corporation.
Copyright (c) 2011, Google Inc.
(c) 1997-2005 Sean Eron Anderson.
Copyright (c) 1991-2017 Unicode, Inc.
Portions (c) International Organization
Copyright (c) 2015 The Chromium Authors.
Copyright (c) 2004-2006 Intel Corporation
Copyright (c) .NET Foundation Contributors
Copyright (c) .NET Foundation and Contributors
Copyright (c) 2011 Novell, Inc (http://www.novell.com)
Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler
Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors.
Copyright (c) YEAR W3C(r) (MIT, ERCIM, Keio, Beihang). Disclaimers THIS WORK IS PROVIDED AS

The MIT License (MIT)

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


---------------------------------------------------------

---------------------------------------------------------

System.Runtime.CompilerServices.Unsafe 6.1.0 - MIT


(c) Microsoft Corporation

MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---------------------------------------------------------

---------------------------------------------------------

System.Threading.Tasks.Extensions 4.5.4 - MIT


(c) 2023 GitHub, Inc.
(c) Microsoft Corporation
Copyright (c) 2011, Google Inc.
(c) 1997-2005 Sean Eron Anderson
Copyright (c) 1991-2017 Unicode, Inc.
Copyright (c) 2015 The Chromium Authors
Portions (c) International Organization
Copyright (c) 2004-2006 Intel Corporation
Copyright (c) .NET Foundation Contributors
Copyright (c) .NET Foundation and Contributors
Copyright (c) 2011 Novell, Inc (http://www.novell.com)
Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler
Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors
Copyright (c) YEAR W3C(r) (MIT, ERCIM, Keio, Beihang). Disclaimers

The MIT License (MIT)

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


---------------------------------------------------------
```

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

## Browser runtime components (8)

Bundled into the admin, user, public, setup and docs interfaces.

| Package | Version | Licence | Source |
| --- | --- | --- | --- |
| cookie | 1.1.1 | MIT | jshttp/cookie |
| qrcode-generator | 2.0.4 | MIT | https://github.com/kazuhikoarase/qrcode-generator |
| react | 19.3.0 | MIT | https://github.com/react/react |
| react-dom | 19.3.0 | MIT | https://github.com/react/react |
| react-router | 7.18.2 | MIT | https://github.com/remix-run/react-router |
| react-router-dom | 7.18.2 | MIT | https://github.com/remix-run/react-router |
| scheduler | 0.28.0 | MIT | https://github.com/react/react |
| set-cookie-parser | 2.7.2 | MIT | nfriedly/set-cookie-parser |

## Vendored assets (2)

Copied into the source tree and bundled into every interface, so no package manager
lists them. Each is named by the `vendored.json` beside it.

| Asset | Version | Licence | Copyright | Source |
| --- | --- | --- | --- | --- |
| [IBM Plex Mono](https://github.com/IBM/plex) | 5.3.0 | OFL-1.1 | Copyright 2017 IBM Corp. | @fontsource/ibm-plex-mono 5.3.0, latin subset, `shared/common/src/theme/fonts` |
| [IBM Plex Sans](https://github.com/IBM/plex) | 5.3.0 | OFL-1.1 | Copyright 2019 IBM Corp. | @fontsource/ibm-plex-sans 5.3.0, latin subset, `shared/common/src/theme/fonts` |

### Licence: IBM Plex Mono, IBM Plex Sans

```text
IBM Plex Sans: Copyright 2019 IBM Corp. All rights reserved.
IBM Plex Mono: Copyright 2017 IBM Corp. All rights reserved.

Latin subsets as published in @fontsource/ibm-plex-sans 5.3.0 and @fontsource/ibm-plex-mono 5.3.0.

This Font Software is licensed under the SIL Open Font License, Version 1.1.
This license is copied below, and is also available with a FAQ at:
http://scripts.sil.org/OFL


-----------------------------------------------------------
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```

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

