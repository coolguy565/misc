using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Diagnostics;
using CmlLib.Core;
using CmlLib.Core.Auth;
using CmlLib.Core.Auth.Microsoft;
using CmlLib.Core.Installers;
using CmlLib.Core.ProcessBuilder;
using CmlLib.Core.VersionMetadata;
using Spectre.Console;

namespace LegacyLauncher
{
    internal class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll")]
        static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll")]
        static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

        const int STD_OUTPUT_HANDLE = -11;
        const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;

        static string GetArg(string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == name && i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                    return args[i + 1];
                if (args[i].StartsWith(name + "="))
                    return args[i].Substring(name.Length + 1);
            }
            return null;
        }

        static bool HasArg(string[] args, string name) =>
            args.Any(a => a == name);

        static bool HasAnsi;

        static byte[] GetKey()
        {
            const int shift = -3;
            var obfuscated = new[] { "6$5", "-&", "Vu", "h&", "('" };
            var sb = new StringBuilder();
            for (int i = obfuscated.Length - 1; i >= 0; i--)
                for (int j = obfuscated[i].Length - 1; j >= 0; j--)
                    sb.Append((char)(obfuscated[i][j] + shift));
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        static byte[] Encrypt(string plain)
        {
            using var aes = Aes.Create();
            aes.Key = GetKey();
            aes.GenerateIV();
            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length);
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
                sw.Write(plain);
            return ms.ToArray();
        }

        static string Decrypt(byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key = GetKey();
            var iv = new byte[16];
            Array.Copy(data, iv, 16);
            aes.IV = iv;
            using var ms = new MemoryStream(data, 16, data.Length - 16);
            using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }

        static async Task<MSession> LoginMicrosoftAsync(string savedUrl = null)
        {
            const string clientId = "00000000402b5328";
            const string redirectUri = "https://login.live.com/oauth20_desktop.srf";
            const string scope = "service::user.auth.xboxlive.com::MBI_SSL";

            var authUrl = "https://login.live.com/oauth20_authorize.srf" +
                "?client_id=" + clientId +
                "&response_type=code" +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&scope=" + Uri.EscapeDataString(scope);

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            string accessToken = null;
            string resultUrl = null;

            while (accessToken == null)
            {
                if (savedUrl != null)
                {
                    resultUrl = savedUrl;
                    savedUrl = null;
                }
                else
                {
                    Process.Start(new ProcessStartInfo(authUrl) { UseShellExecute = true });

                    Console.WriteLine("After logging in, copy the FULL address bar URL and paste it here (be quick — the code expires fast):");
                    resultUrl = Console.ReadLine()?.Trim();
                    if (string.IsNullOrEmpty(resultUrl))
                        throw new Exception("No URL was provided.");

                    if (resultUrl.Contains("removed=true"))
                    {
                        Console.WriteLine("You were too slow — the page redirected to ?removed=true. Try again and copy faster.");
                        continue;
                    }
                }

                var query = new Uri(resultUrl).Query;
                var code = ParseQueryString(query).FirstOrDefault(kv => kv.Key == "code").Value;
                if (code == null)
                    throw new Exception("No authorization code found in the URL.");

                var tokenResponse = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                    await (await http.PostAsync("https://login.live.com/oauth20_token.srf",
                        new FormUrlEncodedContent(new Dictionary<string, string>
                        {
                            ["client_id"] = clientId,
                            ["code"] = code,
                            ["grant_type"] = "authorization_code",
                            ["redirect_uri"] = redirectUri,
                            ["scope"] = scope
                        }))).Content.ReadAsStringAsync());

                if (tokenResponse.TryGetValue("access_token", out var at))
                {
                    accessToken = at.GetString();
                    break;
                }

                string errorMsg = "Unknown error";
                if (tokenResponse.TryGetValue("error", out var errEl))
                    errorMsg = errEl.GetString();
                if (tokenResponse.TryGetValue("error_description", out var descEl))
                    errorMsg += " - " + descEl.GetString();
                Console.WriteLine($"Error: {errorMsg}");
                Console.WriteLine("Press Enter to retry...");
                Console.ReadLine();
            }

            var xblBody = await (await http.PostAsync("https://user.auth.xboxlive.com/user/authenticate",
                new StringContent(JsonSerializer.Serialize(new
                {
                    RelyingParty = "http://auth.xboxlive.com",
                    TokenType = "JWT",
                    Properties = new
                    {
                        AuthMethod = "RPS",
                        SiteName = "user.auth.xboxlive.com",
                        RpsTicket = "t=" + accessToken
                    }
                }), Encoding.UTF8, "application/json"))).Content.ReadAsStringAsync();

            var xblResponse = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(xblBody);
            if (!xblResponse.TryGetValue("Token", out var xblTokenEl) ||
                !xblResponse.TryGetValue("DisplayClaims", out var dcEl))
            {
                var xErr = xblResponse.TryGetValue("XErr", out var xe) ? xe.GetInt64() : -1;
                var msg = xblResponse.TryGetValue("Message", out var me) ? me.GetString() : xblBody;
                throw new Exception($"XBL auth failed (XErr={xErr}): {msg}");
            }

            var xblToken = xblTokenEl.GetString();
            var xui = dcEl.GetProperty("xui");
            if (xui.ValueKind != JsonValueKind.Array || xui.GetArrayLength() == 0)
                throw new Exception("XBL response missing xui array.");

            var xstsBody = await (await http.PostAsync("https://xsts.auth.xboxlive.com/xsts/authorize",
                new StringContent(JsonSerializer.Serialize(new
                {
                    RelyingParty = "rp://api.minecraftservices.com/",
                    TokenType = "JWT",
                    Properties = new
                    {
                        SandboxId = "RETAIL",
                        UserTokens = new[] { xblToken }
                    }
                }), Encoding.UTF8, "application/json"))).Content.ReadAsStringAsync();

            var xstsResponse = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(xstsBody);
            if (!xstsResponse.TryGetValue("Token", out var xstsTokenEl) ||
                !xstsResponse.TryGetValue("DisplayClaims", out var xstsDcEl))
            {
                var xErr = xstsResponse.TryGetValue("XErr", out var xe) ? xe.GetInt64() : -1;
                var msg = xstsResponse.TryGetValue("Message", out var me) ? me.GetString() : xstsBody;
                string hint = "";
                if (xErr == 2148916233) hint = " (No Xbox Live account linked to this Microsoft account)";
                else if (xErr == 2148916235) hint = " (Minecraft not purchased on this account)";
                else if (xErr == 2148916238) hint = " (Child account needs parental consent)";
                throw new Exception($"XSTS auth failed (XErr={xErr}){hint}: {msg}");
            }

            var xstsToken = xstsTokenEl.GetString();
            var xstsXui = xstsDcEl.GetProperty("xui");
            if (xstsXui.ValueKind != JsonValueKind.Array || xstsXui.GetArrayLength() == 0)
                throw new Exception("XSTS response missing xui array.");

            var xstsUhs = xstsXui[0].GetProperty("uhs").GetString();

            var mcBody = await (await http.PostAsync("https://api.minecraftservices.com/authentication/login_with_xbox",
                new StringContent(JsonSerializer.Serialize(new
                {
                    identityToken = "XBL3.0 x=" + xstsUhs + ";" + xstsToken,
                    ensureLegacyEnabled = true
                }), Encoding.UTF8, "application/json"))).Content.ReadAsStringAsync();

            var mcResponse = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(mcBody);
            if (!mcResponse.TryGetValue("access_token", out var mcTokenEl))
            {
                var err = mcResponse.TryGetValue("error", out var ee) ? ee.GetString() : mcBody;
                var desc = mcResponse.TryGetValue("errorMessage", out var de) ? de.GetString() : "";
                throw new Exception($"Minecraft auth failed: {err} {desc}");
            }

            var mcAccessToken = mcTokenEl.GetString();

            var profileBody = await (await http.SendAsync(new HttpRequestMessage(HttpMethod.Get,
                "https://api.minecraftservices.com/minecraft/profile")
            {
                Headers = { { "Authorization", "Bearer " + mcAccessToken } }
            })).Content.ReadAsStringAsync();

            var profileResponse = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(profileBody);
            if (!profileResponse.TryGetValue("id", out var idEl) ||
                !profileResponse.TryGetValue("name", out var nameEl))
            {
                var err = profileResponse.TryGetValue("error", out var ee) ? ee.GetString() : profileBody;
                var desc = profileResponse.TryGetValue("errorMessage", out var de) ? de.GetString() : "";
                throw new Exception($"Minecraft profile fetch failed: {err} {desc}");
            }

            File.WriteAllBytes("TOKENS.txt", Encrypt(resultUrl));

            return new MSession
            {
                Username = nameEl.GetString(),
                UUID = idEl.GetString(),
                AccessToken = mcAccessToken,
                UserType = "Mojang",
                ClientToken = null
            };
        }

        static IEnumerable<KeyValuePair<string, string>> ParseQueryString(string query)
        {
            if (query.StartsWith("?"))
                query = query.Substring(1);
            foreach (var part in query.Split('&'))
            {
                var eq = part.IndexOf('=');
                if (eq > 0)
                    yield return new KeyValuePair<string, string>(
                        Uri.UnescapeDataString(part.Substring(0, eq)),
                        Uri.UnescapeDataString(part.Substring(eq + 1)));
            }
        }

        static async Task Main(string[] args)
        {
            try
            {
            System.Net.ServicePointManager.SecurityProtocol =
                System.Net.SecurityProtocolType.Tls12 |
                System.Net.SecurityProtocolType.Tls11 |
                System.Net.SecurityProtocolType.Tls;

            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;
            var handle = GetStdHandle(STD_OUTPUT_HANDLE);
            if (GetConsoleMode(handle, out var mode))
                SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

            var hideConsole = HasArg(args, "--hideconsole");
            if (hideConsole)
                ShowWindow(GetConsoleWindow(), 0);

            HasAnsi = AnsiConsole.Profile.Capabilities.Ansi && !hideConsole;

            var sessionTypeArg = GetArg(args, "--sessiontype");
            var playerArg = GetArg(args, "--player");

            string sessionType;
            if (sessionTypeArg != null &&
                (sessionTypeArg.ToLower() == "offline" || sessionTypeArg.ToLower() == "online"))
            {
                sessionType = sessionTypeArg.ToLower() == "offline" ? "Offline" : "Online (Microsoft)";
            }
            else if (HasAnsi)
            {
                sessionType = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("Select session type")
                        .AddChoices("Offline", "Online (Microsoft)"));
            }
            else
            {
                Console.WriteLine("Select session type:");
                Console.WriteLine("  1. Offline");
                Console.WriteLine("  2. Online (Microsoft)");
                Console.Write("Choose (1-2): ");
                sessionType = Console.ReadLine()?.Trim() == "2" ? "Online (Microsoft)" : "Offline";
            }

            string savedUrl = null;
            if (sessionTypeArg == null && File.Exists("TOKENS.txt"))
            {
                if (HasAnsi)
                {
                    if (AnsiConsole.Confirm("Saved online session found. Use it?"))
                        savedUrl = Decrypt(File.ReadAllBytes("TOKENS.txt")).Trim();
                    else
                        File.Delete("TOKENS.txt");
                }
                else
                {
                    Console.Write("Saved online session found. Use it? (y/n): ");
                    if (Console.ReadLine()?.Trim().ToLower() == "y")
                        savedUrl = Decrypt(File.ReadAllBytes("TOKENS.txt")).Trim();
                    else
                        File.Delete("TOKENS.txt");
                }
            }

            MSession session = MSession.CreateOfflineSession("Player");
            if (sessionType == "Offline")
            {
                string username;
                if (playerArg != null)
                {
                    username = playerArg;
                }
                else if (HasAnsi)
                {
                    username = AnsiConsole.Ask<string>("Enter [green]username[/]:");
                }
                else
                {
                    Console.Write("Enter username: ");
                    username = Console.ReadLine() ?? "Player";
                }
                session = MSession.CreateOfflineSession(username);
            }
            else
            {
                try
                {
                    if (HasAnsi)
                        session = await AnsiConsole.Status()
                            .StartAsync("Authenticating...", ctx => LoginMicrosoftAsync(savedUrl));
                    else
                    {
                        Console.WriteLine("Authenticating...");
                        session = await LoginMicrosoftAsync(savedUrl);
                    }
                }
                catch (Exception ex)
                {
                    if (HasAnsi)
                        AnsiConsole.MarkupLine($"[red]{ex.Message}[/]");
                    else
                        Console.WriteLine(ex.Message);
                    if (HasAnsi)
                        AnsiConsole.MarkupLine("[yellow]Falling back to offline mode.[/]");
                    else
                        Console.WriteLine("Falling back to offline mode.");
                    session = MSession.CreateOfflineSession("Player");
                }
            }

            var launcher = new MinecraftLauncher();
            var versions = await launcher.GetAllVersionsAsync();

                var versionArg = GetArg(args, "--version");
                string selectedVersion;

                if (versionArg != null)
                {
                    selectedVersion = versionArg;
                    if (!versions.Any(v => v.Name == selectedVersion))
                    {
                        if (HasAnsi)
                            AnsiConsole.MarkupLine($"[red]Version '{selectedVersion}' not found.[/]");
                        else
                            Console.WriteLine($"Version '{selectedVersion}' not found.");
                        return;
                    }
                    if (HasAnsi)
                        AnsiConsole.MarkupLine($"[grey]Using version: {selectedVersion}[/]");
                    else
                        Console.WriteLine($"Using version: {selectedVersion}");
                }
                else if (HasAnsi)
                {
                    var versionChoices = versions
                        .Where(v => v.Type == "release")
                        .Select(v =>
                        {
                            var meta = v as JsonVersionMetadata;
                            var installed = meta != null && meta.IsSaved;
                            return installed ? $"{v.Name} [green](installed)[/]" : v.Name;
                        })
                        .ToList();

                    selectedVersion = AnsiConsole.Prompt(
                        new SelectionPrompt<string>()
                            .Title("Select Minecraft version")
                            .PageSize(20)
                            .MoreChoicesText("[grey](scroll for more)[/]")
                            .AddChoices(versionChoices));

                    selectedVersion = selectedVersion.Split(' ')[0];
                }
                else
                {
                    var releaseNames = versions
                        .Where(v => v.Type == "release")
                        .Select(v => v.Name)
                        .ToList();

                    Console.WriteLine("Select Minecraft version:");
                    for (int i = 0; i < releaseNames.Count; i++)
                        Console.WriteLine($"  {i + 1}. {releaseNames[i]}");
                    Console.Write($"Choose (1-{releaseNames.Count}): ");
                    if (!int.TryParse(Console.ReadLine(), out var idx))
                        idx = 1;
                    idx -= 1;
                    selectedVersion = releaseNames[Math.Max(0, Math.Min(idx, releaseNames.Count - 1))];
                }

                int ramMb;
                var ramArg = GetArg(args, "--ram");
                if (ramArg != null && int.TryParse(ramArg, out ramMb) && ramMb >= 512)
                {
                    if (HasAnsi)
                        AnsiConsole.MarkupLine($"[grey]RAM: {ramMb}MB[/]");
                    else
                        Console.WriteLine($"RAM: {ramMb}MB");
                }
                else if (HasAnsi)
                {
                    ramMb = AnsiConsole.Prompt(
                        new TextPrompt<int>("Enter [green]RAM (MB)[/]:")
                            .DefaultValue(2048)
                            .Validate(v => v >= 512 ? ValidationResult.Success() : ValidationResult.Error("[red]Minimum 512MB[/]")));
                }
                else
                {
                    Console.Write("Enter RAM (MB) [2048]: ");
                    if (!int.TryParse(Console.ReadLine(), out ramMb) || ramMb < 512)
                        ramMb = 2048;
                }

                var serverArg = GetArg(args, "--server");
                var widthArg = GetArg(args, "--width");
                var heightArg = GetArg(args, "--height");
                var javaArg = GetArg(args, "--java");
                var jvmArgsArg = GetArg(args, "--jvmargs");

                var versionMeta = versions.First(v => v.Name == selectedVersion);
                bool isInstalled = (versionMeta as JsonVersionMetadata)?.IsSaved ?? false;

                if (!isInstalled)
                {
                    if (HasAnsi)
                    {
                        AnsiConsole.Progress()
                            .Columns(new ProgressColumn[]
                            {
                                new TaskDescriptionColumn(),
                                new ProgressBarColumn(),
                                new PercentageColumn(),
                                new RemainingTimeColumn()
                            })
                            .Start(ctx =>
                            {
                                var task = ctx.AddTask($"Installing {selectedVersion}");
                                task.IsIndeterminate = false;

                                launcher.FileProgressChanged += (s, e) =>
                                {
                                    task.MaxValue = e.TotalTasks;
                                    task.Value = e.ProgressedTasks;
                                    task.Description = $"[grey]{e.Name}[/]";
                                };

                                launcher.InstallAsync(selectedVersion).GetAwaiter().GetResult();
                                task.Value = task.MaxValue;
                            });
                    }
                    else
                    {
                        Console.WriteLine($"Installing {selectedVersion}...");
                        launcher.InstallAsync(selectedVersion).GetAwaiter().GetResult();
                        Console.WriteLine("Done.");
                    }
                }
                else
                {
                    if (HasAnsi)
                        AnsiConsole.MarkupLine($"[grey]Minecraft {selectedVersion} already installed, skipping...[/]");
                    else
                        Console.WriteLine($"Minecraft {selectedVersion} already installed, skipping...");
                }

                var launchOption = new MLaunchOption
                {
                    Session = session,
                    MaximumRamMb = ramMb,
                };

                if (serverArg != null)
                {
                    var parts = serverArg.Split(':');
                    launchOption.ServerIp = parts[0];
                    if (parts.Length > 1 && int.TryParse(parts[1], out var port))
                        launchOption.ServerPort = port;
                    if (HasAnsi)
                        AnsiConsole.MarkupLine($"[grey]Server: {serverArg}[/]");
                    else
                        Console.WriteLine($"Server: {serverArg}");
                }

                if (widthArg != null && int.TryParse(widthArg, out var w))
                    launchOption.ScreenWidth = w;
                if (heightArg != null && int.TryParse(heightArg, out var h))
                    launchOption.ScreenHeight = h;

                if (javaArg != null)
                    launchOption.JavaPath = javaArg;

                if (jvmArgsArg != null)
                {
                    launchOption.ExtraJvmArguments = new[] { MArgument.FromCommandLine(jvmArgsArg) };
                    if (HasAnsi)
                        AnsiConsole.MarkupLine($"[grey]JVM args: {jvmArgsArg}[/]");
                    else
                        Console.WriteLine($"JVM args: {jvmArgsArg}");
                }

                var process = await launcher.BuildProcessAsync(selectedVersion, launchOption);

                if (HasAnsi)
                    AnsiConsole.MarkupLine("[green]Launching...[/]");
                else
                    Console.WriteLine("Launching...");
                process.Start();
            }
            catch (Exception ex)
            {
                if (HasAnsi)
                    AnsiConsole.MarkupLine($"[red]{ex.Message}[/]");
                else
                    Console.WriteLine(ex.Message);
            }
        }
    }
}
