using System.IO;
using System.Text.Json;
using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Core.Scanners;

public class BrowserExtensionScanner : IScanner
{
    public string Name => "Browser Extensions";
    public ScanPhase Phase => ScanPhase.ScanningBrowsers;

    private readonly ILogger _logger;

    public BrowserExtensionScanner(ILogger logger)
    {
        _logger = logger;
    }

    public async Task<IEnumerable<ScanItemBase>> ScanAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        var extensions = new List<BrowserExtensionInfo>();

        if (!context.Settings.ScanBrowserExtensions)
        {
            _logger.Information("Browser extension scanning disabled in settings");
            return extensions;
        }

        try
        {
            context.Progress?.Report(new ScanProgress
            {
                CurrentPhase = Phase,
                StatusMessage = "Scanning browser extensions..."
            });

            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var chromiumBrowsers = new (string Browser, string Root)[]
            {
                ("Chrome", Path.Combine(localAppData, "Google", "Chrome", "User Data")),
                ("Edge", Path.Combine(localAppData, "Microsoft", "Edge", "User Data"))
            };

            foreach (var (browser, root) in chromiumBrowsers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                foreach (var profileDir in EnumerateProfileDirs(root))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    extensions.AddRange(await ScanChromiumProfileAsync(browser, profileDir, cancellationToken));
                }
            }

            var firefoxProfiles = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(firefoxProfiles))
            {
                foreach (var profileDir in Directory.EnumerateDirectories(firefoxProfiles))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    extensions.AddRange(await ScanFirefoxProfileAsync(profileDir, cancellationToken));
                }
            }

            foreach (var ext in extensions)
            {
                ext.RiskAssessment = AnalyzeExtension(ext);
            }

            _logger.Information("Browser extension scan completed: {Count} extensions found", extensions.Count);
        }
        catch (OperationCanceledException)
        {
            _logger.Warning("Browser extension scan cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Browser extension scan failed");
        }

        return extensions;
    }

    private static IEnumerable<string> EnumerateProfileDirs(string userDataRoot)
    {
        var profileNames = new[] { "Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5" };
        var profiles = new List<string>();
        foreach (var name in profileNames)
        {
            var dir = Path.Combine(userDataRoot, name);
            if (File.Exists(Path.Combine(dir, "Preferences"))) profiles.Add(dir);
        }

        try
        {
            foreach (var dir in Directory.EnumerateDirectories(userDataRoot))
            {
                if (profiles.Contains(dir)) continue;
                if (File.Exists(Path.Combine(dir, "Preferences"))) profiles.Add(dir);
            }
        }
        catch
        {
            // ignore enumeration errors
        }

        return profiles;
    }

    private async Task<List<BrowserExtensionInfo>> ScanChromiumProfileAsync(string browser, string profileDir, CancellationToken ct)
    {
        var result = new List<BrowserExtensionInfo>();

        try
        {
            var prefsPath = Path.Combine(profileDir, "Preferences");
            if (!File.Exists(prefsPath)) return result;

            await using var stream = File.OpenRead(prefsPath);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

            if (!doc.RootElement.TryGetProperty("extensions", out var extensions) ||
                !extensions.TryGetProperty("settings", out var settings) ||
                settings.ValueKind != JsonValueKind.Object)
            {
                return result;
            }

            foreach (var property in settings.EnumerateObject())
            {
                ct.ThrowIfCancellationRequested();
                var item = ParseChromiumExtension(browser, profileDir, property.Name, property.Value);
                if (item != null) result.Add(item);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.Warning("Failed to parse {Browser} profile {Profile}: {Error}", browser, profileDir, ex.Message);
        }

        return result;
    }

    private static BrowserExtensionInfo? ParseChromiumExtension(string browser, string profileDir, string extensionId, JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) return null;

        var manifest = value.TryGetProperty("manifest", out var m) && m.ValueKind == JsonValueKind.Object
            ? m
            : default;

        var name = manifest.ValueKind == JsonValueKind.Object && manifest.TryGetProperty("name", out var nameEl)
            ? nameEl.GetString()
            : null;
        if (string.IsNullOrWhiteSpace(name) || name.StartsWith("__MSG_", StringComparison.Ordinal))
        {
            name = extensionId;
        }

        var version = manifest.ValueKind == JsonValueKind.Object && manifest.TryGetProperty("version", out var verEl)
            ? verEl.GetString()
            : string.Empty;

        var description = manifest.ValueKind == JsonValueKind.Object && manifest.TryGetProperty("description", out var descEl)
            ? descEl.GetString()
            : string.Empty;

        var permissions = new List<string>();
        if (manifest.ValueKind == JsonValueKind.Object && manifest.TryGetProperty("permissions", out var perms) &&
            perms.ValueKind == JsonValueKind.Array)
        {
            permissions.AddRange(perms.EnumerateArray()
                .Where(p => p.ValueKind == JsonValueKind.String)
                .Select(p => p.GetString()!));
        }

        var fromWebstore = value.TryGetProperty("from_webstore", out var store) && store.ValueKind == JsonValueKind.True;
        var updateUrl = value.TryGetProperty("update_url", out var upd) ? upd.GetString() ?? string.Empty : string.Empty;
        if (!fromWebstore && !string.IsNullOrWhiteSpace(updateUrl))
        {
            fromWebstore = updateUrl.Contains("clients2.google.com", StringComparison.OrdinalIgnoreCase)
                        || updateUrl.Contains("edge.microsoft.com", StringComparison.OrdinalIgnoreCase);
        }

        var enabled = !value.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.Number || state.GetInt32() != 0;

        var author = string.Empty;
        if (manifest.ValueKind == JsonValueKind.Object && manifest.TryGetProperty("author", out var authorEl))
        {
            author = authorEl.ValueKind switch
            {
                JsonValueKind.String => authorEl.GetString() ?? string.Empty,
                JsonValueKind.Object when authorEl.TryGetProperty("name", out var authorName) => authorName.GetString() ?? string.Empty,
                _ => string.Empty
            };
        }

        var homepage = manifest.ValueKind == JsonValueKind.Object && manifest.TryGetProperty("homepage_url", out var home)
            ? home.GetString() ?? string.Empty
            : string.Empty;

        var installPath = Path.Combine(profileDir, "Extensions", extensionId);

        return new BrowserExtensionInfo
        {
            Browser = browser,
            ExtensionId = extensionId,
            ExtensionName = name,
            Version = version ?? string.Empty,
            Description = description ?? string.Empty,
            InstallPath = installPath,
            IsEnabled = enabled,
            Permissions = string.Join(", ", permissions),
            UpdateUrl = updateUrl,
            HomepageUrl = homepage,
            IsFromStore = fromWebstore,
            Publisher = author,
            IsSigned = fromWebstore,
            SignatureValid = fromWebstore,
            IsSystemItem = false,
            CanStop = false,
            CanDisable = false,
            CanDelete = true
        };
    }

    private async Task<List<BrowserExtensionInfo>> ScanFirefoxProfileAsync(string profileDir, CancellationToken ct)
    {
        var result = new List<BrowserExtensionInfo>();

        try
        {
            var extensionsPath = Path.Combine(profileDir, "extensions.json");
            if (!File.Exists(extensionsPath)) return result;

            await using var stream = File.OpenRead(extensionsPath);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

            if (doc.RootElement.ValueKind != JsonValueKind.Array) return result;

            foreach (var addon in doc.RootElement.EnumerateArray())
            {
                ct.ThrowIfCancellationRequested();
                if (addon.ValueKind != JsonValueKind.Object) continue;
                if (addon.TryGetProperty("type", out var type) &&
                    !string.Equals(type.GetString(), "extension", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                result.Add(ParseFirefoxAddon(profileDir, addon));
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.Warning("Failed to parse Firefox profile {Profile}: {Error}", profileDir, ex.Message);
        }

        return result;
    }

    private static BrowserExtensionInfo ParseFirefoxAddon(string profileDir, JsonElement addon)
    {
        var id = addon.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? string.Empty : Guid.NewGuid().ToString();

        var name = ReadLocalizedName(addon, "name");
        var description = ReadLocalizedName(addon, "description");
        var version = addon.TryGetProperty("version", out var ver) ? ver.GetString() ?? string.Empty : string.Empty;
        var sourceUri = addon.TryGetProperty("sourceURI", out var src) ? src.GetString() ?? string.Empty : string.Empty;
        var path = addon.TryGetProperty("path", out var p) ? p.GetString() ?? string.Empty : string.Empty;
        var signedState = addon.TryGetProperty("signedState", out var ss) && ss.ValueKind == JsonValueKind.Number
            ? ss.GetInt32()
            : -1;
        var active = !addon.TryGetProperty("active", out var act) || act.ValueKind != JsonValueKind.False;
        var userDisabled = addon.TryGetProperty("userDisabled", out var ud) && ud.ValueKind == JsonValueKind.True;
        var appDisabled = addon.TryGetProperty("appDisabled", out var ad) && ad.ValueKind == JsonValueKind.True;

        var permissions = new List<string>();
        if (addon.TryGetProperty("permissions", out var perms))
        {
            if (perms.ValueKind == JsonValueKind.Array)
            {
                permissions.AddRange(perms.EnumerateArray()
                    .Where(x => x.ValueKind == JsonValueKind.String)
                    .Select(x => x.GetString()!));
            }
            else if (perms.ValueKind == JsonValueKind.Object)
            {
                permissions.AddRange(perms.EnumerateObject()
                    .Where(x => x.Value.ValueKind == JsonValueKind.True)
                    .Select(x => x.Name));
            }
        }

        var homepage = string.Empty;
        if (addon.TryGetProperty("homepageURL", out var home)) homepage = home.GetString() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(homepage) && addon.TryGetProperty("homepage", out var homeObj) &&
            homeObj.ValueKind == JsonValueKind.Object && homeObj.TryGetProperty("url", out var homeUrl))
        {
            homepage = homeUrl.GetString() ?? string.Empty;
        }

        var isSigned = signedState >= 2;
        var installPath = string.IsNullOrWhiteSpace(path) ? Path.Combine(profileDir, "extensions", id) : path;

        return new BrowserExtensionInfo
        {
            Browser = "Firefox",
            ExtensionId = id,
            ExtensionName = string.IsNullOrWhiteSpace(name) ? id : name,
            Version = version,
            Description = description,
            InstallPath = installPath,
            IsEnabled = active && !userDisabled && !appDisabled,
            Permissions = string.Join(", ", permissions),
            UpdateUrl = sourceUri,
            HomepageUrl = homepage,
            IsFromStore = sourceUri.Contains("addons.mozilla.org", StringComparison.OrdinalIgnoreCase),
            Publisher = "Mozilla Add-ons",
            IsSigned = isSigned,
            SignatureValid = signedState == 4,
            IsSystemItem = false,
            CanStop = false,
            CanDisable = false,
            CanDelete = true
        };
    }

    private static string ReadLocalizedName(JsonElement addon, string propertyName)
    {
        if (!addon.TryGetProperty(propertyName, out var value)) return string.Empty;

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Object => ReadLocaleObject(value),
            _ => string.Empty
        };
    }

    private static string ReadLocaleObject(JsonElement value)
    {
        foreach (var preferred in new[] { "ru", "en-US", "en" })
        {
            if (value.TryGetProperty(preferred, out var localized) && localized.ValueKind == JsonValueKind.String)
            {
                return localized.GetString() ?? string.Empty;
            }
        }

        foreach (var property in value.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.String)
            {
                return property.Value.GetString() ?? string.Empty;
            }
        }

        return string.Empty;
    }

    private static RiskAssessment AnalyzeExtension(BrowserExtensionInfo ext)
    {
        var factors = new List<RiskFactor>();

        if (!ext.IsFromStore)
        {
            factors.Add(new RiskFactor
            {
                Id = "EXT_SIDELOAD",
                Category = "Provenance",
                Description = "Расширение установлено не из официального магазина",
                Score = 35,
                Severity = RiskSeverity.High,
                Evidence = $"{ext.Browser}: {ext.ExtensionId}",
                Recommendation = "Сайдлоад-расширения распространяются вне магазинов и часто оказываются вредоносными."
            });
        }

        var permissions = ext.Permissions.ToLowerInvariant();
        if (permissions.Contains("<all_urls>") || permissions.Contains("http://*/*") || permissions.Contains("<all_urls>"))
        {
            factors.Add(new RiskFactor
            {
                Id = "EXT_ALL_URLS",
                Category = "Permissions",
                Description = "Расширение запрашивает доступ ко всем сайтам",
                Score = 25,
                Severity = RiskSeverity.High,
                Evidence = $"Разрешения: {ext.Permissions}",
                Recommendation = "Доступ ко всем URL позволяет читать содержимое любых открытых страниц."
            });
        }

        if (permissions.Contains("debugger") || permissions.Contains("native messaging") || permissions.Contains("nativemessaging") ||
            permissions.Contains("proxy"))
        {
            factors.Add(new RiskFactor
            {
                Id = "EXT_DANGEROUS_PERMISSION",
                Category = "Permissions",
                Description = "Расширение имеет опасные разрешения (отладка/нативные сообщения/прокси)",
                Score = 30,
                Severity = RiskSeverity.High,
                Evidence = $"Разрешения: {ext.Permissions}",
                Recommendation = "Такие разрешения дают полный контроль над браузером и системой."
            });
        }

        if (ext.Browser == "Firefox" && !ext.IsSigned)
        {
            factors.Add(new RiskFactor
            {
                Id = "EXT_UNSIGNED",
                Category = "Signature",
                Description = "Расширение Firefox не подписано Mozilla",
                Score = 15,
                Severity = RiskSeverity.Medium,
                Evidence = $"ID: {ext.ExtensionId}",
                Recommendation = "Неподписанные расширения не проходят проверку подлинности."
            });
        }

        if (!ext.IsEnabled)
        {
            factors.Add(new RiskFactor
            {
                Id = "EXT_DISABLED",
                Category = "State",
                Description = "Расширение отключено",
                Score = 5,
                Severity = RiskSeverity.Informational,
                Evidence = $"ID: {ext.ExtensionId}",
                Recommendation = "Отключённое расширение не активно, но может быть повторно включено."
            });
        }

        var assessment = new RiskAssessment { Factors = factors };
        assessment.TotalScore = Math.Max(0, Math.Min(100, factors.Sum(f => f.Score)));
        assessment.Level = assessment.TotalScore switch
        {
            >= 80 => RiskLevel.Critical,
            >= 60 => RiskLevel.High,
            >= 40 => RiskLevel.Medium,
            >= 20 => RiskLevel.Low,
            _ => RiskLevel.Informational
        };

        return assessment;
    }
}
