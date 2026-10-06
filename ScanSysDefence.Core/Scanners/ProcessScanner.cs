using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;
using ScanSysDefence.Native.Win32;

namespace ScanSysDefence.Core.Scanners;

public class ProcessScanner : IScanner
{
    public string Name => "Processes";
    public ScanPhase Phase => ScanPhase.ScanningProcesses;

    /// <summary>Максимальный объём выборки файла для оценки энтропии (1 МБ).</summary>
    private const int MaxEntropySampleBytes = 1024 * 1024;

    private readonly ILogger _logger;
    private readonly IDigitalSignatureService _signatureService;

    public ProcessScanner(ILogger logger, IDigitalSignatureService signatureService)
    {
        _logger = logger;
        _signatureService = signatureService;
    }

    public async Task<IEnumerable<ScanItemBase>> ScanAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        var processes = new List<ProcessInfo>();

        try
        {
            context.Progress?.Report(new ScanProgress
            {
                CurrentPhase = Phase,
                StatusMessage = "Перечисление процессов..."
            });

            // Один общий WMI-запрос вместо трёх запросов на каждый процесс
            var wmiInfo = await Task.Run(QueryWmiProcessInfo, cancellationToken);

            var allProcesses = Process.GetProcesses();
            var total = allProcesses.Length;
            var processed = 0;

            foreach (var proc in allProcesses)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var processInfo = await AnalyzeProcessAsync(proc, wmiInfo, context.Settings);
                    if (processInfo != null)
                    {
                        processes.Add(processInfo);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Failed to analyze process {ProcessName} (PID: {Pid})", proc.ProcessName, proc.Id);
                }
                finally
                {
                    proc.Dispose();
                }

                processed++;
                if (processed % 10 == 0 || processed == total)
                {
                    context.Progress?.Report(new ScanProgress
                    {
                        CurrentPhase = Phase,
                        CurrentPhaseProgress = (int)((double)processed / total * 100),
                        ItemsScanned = processed * 10,
                        StatusMessage = $"Сканирование процессов: {processed}/{total}"
                    });
                }
            }

            // Get network connections for all processes
            if (context.Settings.CheckNetworkConnections)
            {
                await EnrichWithNetworkConnectionsAsync(processes);
            }

            _logger.Information("Process scan completed: {Count} processes analyzed", processes.Count);
        }
        catch (OperationCanceledException)
        {
            _logger.Warning("Process scan cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Process scan failed");
        }

        return processes;
    }

    private sealed class WmiProcessInfo
    {
        public string CommandLine { get; set; } = string.Empty;
        public int ParentProcessId { get; set; }
        public string ExecutablePath { get; set; } = string.Empty;
    }

    private static Dictionary<int, WmiProcessInfo> QueryWmiProcessInfo()
    {
        var map = new Dictionary<int, WmiProcessInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine, ParentProcessId, ExecutablePath FROM Win32_Process");
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    var pid = Convert.ToInt32(obj["ProcessId"] ?? 0);
                    if (pid <= 0) continue;
                    map[pid] = new WmiProcessInfo
                    {
                        CommandLine = obj["CommandLine"]?.ToString() ?? string.Empty,
                        ParentProcessId = Convert.ToInt32(obj["ParentProcessId"] ?? 0),
                        ExecutablePath = obj["ExecutablePath"]?.ToString() ?? string.Empty
                    };
                }
                catch
                {
                    // отдельные процессы могут быть недоступны
                }
                finally
                {
                    obj.Dispose();
                }
            }
        }
        catch
        {
            // WMI может быть недоступен — работаем без дополнительных данных
        }
        return map;
    }

    private async Task<ProcessInfo?> AnalyzeProcessAsync(Process proc, Dictionary<int, WmiProcessInfo> wmiInfo, ScanSettings settings)
    {
        try
        {
            var pid = proc.Id;
            wmiInfo.TryGetValue(pid, out var wmi);

            string path = string.Empty;
            try { path = proc.MainModule?.FileName ?? string.Empty; }
            catch { /* Access denied */ }

            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                path = wmi?.ExecutablePath ?? string.Empty;
            }

            if (string.IsNullOrWhiteSpace(path)) return null;

            var signature = await _signatureService.VerifySignatureAsync(path);
            var isMicrosoftSigned = signature.IsValid && IsMicrosoftPublisher(signature.Publisher);
            if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) return null;

            var modules = new List<ModuleInfo>();
            if (settings.DeepProcessAnalysis)
            {
                modules = await GetModulesAsync(proc);
            }

            var versionInfo = GetVersionInfoSafe(path);

            var processInfo = new ProcessInfo
            {
                ProcessId = pid,
                ParentProcessId = wmi?.ParentProcessId ?? 0,
                ProcessName = proc.ProcessName,
                Path = path,
                CommandLine = wmi?.CommandLine ?? string.Empty,
                CommandLineArgs = ParseCommandLine(wmi?.CommandLine ?? string.Empty),
                UserName = ProcessNative.TryGetProcessUser(pid),
                SessionId = GetSessionIdSafe(proc),
                StartTime = GetProcessStartTime(proc),
                TotalProcessorTime = GetTotalProcessorTimeSafe(proc),
                WorkingSet64 = GetWorkingSetSafe(proc),
                PrivateMemorySize64 = GetPrivateMemorySafe(proc),
                VirtualMemorySize64 = GetVirtualMemorySafe(proc),
                ThreadCount = GetThreadCountSafe(proc),
                HandleCount = GetHandleCountSafe(proc),
                IsElevated = ProcessNative.IsProcessElevated(pid),
                IsWow64 = IsProcessWow64(proc),
                IntegrityLevel = ProcessNative.TryGetIntegrityLevel(pid),
                Modules = modules,
                IsSigned = signature.IsSigned,
                SignatureValid = signature.IsValid,
                Publisher = signature.Publisher,
                SignatureDetails = signature.RawDetails,
                CompanyName = versionInfo?.CompanyName ?? string.Empty,
                FileDescription = versionInfo?.FileDescription ?? string.Empty,
                ProductName = versionInfo?.ProductName ?? string.Empty,
                OriginalFilename = versionInfo?.OriginalFilename ?? string.Empty,
                FileVersion = versionInfo?.FileVersion ?? string.Empty,
                IsPacked = DetectPacked(path),
                IsDotNet = IsDotNetAssembly(path),
                IsSystemItem = IsSystemProcess(proc.ProcessName, path, signature.Publisher),
                CanStop = true,
                CanDisable = false,
                CanDelete = !IsSystemProcess(proc.ProcessName, path, signature.Publisher)
            };

            processInfo.RiskAssessment = await RiskAnalyzer.AnalyzeProcessAsync(processInfo, _signatureService);
            return processInfo;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to analyze process {Pid}", proc.Id);
            return null;
        }
    }

    private async Task<List<ModuleInfo>> GetModulesAsync(Process proc)
    {
        var modules = new List<ModuleInfo>();
        ProcessModuleCollection processModules;
        try
        {
            processModules = proc.Modules;
        }
        catch
        {
            return modules;
        }

        foreach (ProcessModule module in processModules)
        {
            try
            {
                var sig = await _signatureService.VerifySignatureAsync(module.FileName);
                var version = GetVersionInfoSafe(module.FileName)?.FileVersion ?? string.Empty;
                modules.Add(new ModuleInfo
                {
                    Name = module.ModuleName,
                    Path = module.FileName,
                    BaseAddress = (long)module.BaseAddress,
                    ModuleMemorySize = module.ModuleMemorySize,
                    FileVersion = version,
                    IsSigned = sig.IsSigned,
                    Publisher = sig.Publisher,
                    IsSuspicious = IsModuleSuspicious(module.FileName, sig)
                });
            }
            catch
            {
                // модуль может выгрузиться во время перечисления
            }
        }
        return modules;
    }

    private static bool IsModuleSuspicious(string path, DigitalSignatureInfo sig)
    {
        if (!sig.IsSigned || !sig.IsValid) return true;
        var lower = path.ToLowerInvariant();
        if (lower.Contains("\\temp\\") || lower.Contains("\\appdata\\")) return true;
        return false;
    }

    private async Task EnrichWithNetworkConnectionsAsync(List<ProcessInfo> processes)
    {
        try
        {
            var connections = await Task.Run(() => NetworkTable.GetTcpEndpoints());
            var udpConnections = await Task.Run(() => NetworkTable.GetUdpEndpoints());

            var tcpByPid = connections.GroupBy(c => c.ProcessId).ToDictionary(g => g.Key, g => g.ToList());
            var udpByPid = udpConnections.GroupBy(c => c.ProcessId).ToDictionary(g => g.Key, g => g.ToList());

            foreach (var proc in processes)
            {
                var procConns = new List<OwningProcessEndpoint>();
                if (tcpByPid.TryGetValue(proc.ProcessId, out var tcp)) procConns.AddRange(tcp);
                if (udpByPid.TryGetValue(proc.ProcessId, out var udp)) procConns.AddRange(udp);

                proc.NetworkConnections = procConns.Select(c => new NetworkConnection
                {
                    LocalAddress = c.LocalAddress.ToString(),
                    LocalPort = c.LocalPort,
                    RemoteAddress = c.RemoteAddress.ToString(),
                    RemotePort = c.RemotePort,
                    State = c.State,
                    Protocol = c.Protocol,
                    ProcessId = c.ProcessId
                }).ToList();
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get network connections");
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(System.IntPtr hProcess, out bool wow64Process);

    private bool IsProcessWow64(Process proc)
    {
        try
        {
            if (!Environment.Is64BitOperatingSystem) return false;
            return IsWow64Process(proc.Handle, out var wow64) && wow64;
        }
        catch
        {
            return false;
        }
    }

    private static string GetSessionIdSafe(Process proc)
    {
        try { return proc.SessionId.ToString(); } catch { return string.Empty; }
    }

    private static DateTime GetProcessStartTime(Process proc)
    {
        try { return proc.StartTime; }
        catch { return DateTime.MinValue; }
    }

    private static TimeSpan GetTotalProcessorTimeSafe(Process proc)
    {
        try { return proc.TotalProcessorTime; } catch { return TimeSpan.Zero; }
    }

    private static long GetWorkingSetSafe(Process proc)
    {
        try { return proc.WorkingSet64; } catch { return 0; }
    }

    private static long GetPrivateMemorySafe(Process proc)
    {
        try { return proc.PrivateMemorySize64; } catch { return 0; }
    }

    private static long GetVirtualMemorySafe(Process proc)
    {
        try { return proc.VirtualMemorySize64; } catch { return 0; }
    }

    private static int GetThreadCountSafe(Process proc)
    {
        try { return proc.Threads.Count; } catch { return 0; }
    }

    private static int GetHandleCountSafe(Process proc)
    {
        try { return proc.HandleCount; } catch { return 0; }
    }

    private static FileVersionInfo? GetVersionInfoSafe(string path)
    {
        try { return FileVersionInfo.GetVersionInfo(path); }
        catch { return null; }
    }

    private string[] ParseCommandLine(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return Array.Empty<string>();
        return commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    private bool DetectPacked(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var length = (int)Math.Min(fs.Length, MaxEntropySampleBytes);
            if (length <= 0) return false;

            var buffer = new byte[length];
            var read = 0;
            while (read < length)
            {
                var n = fs.Read(buffer, read, length - read);
                if (n <= 0) break;
                read += n;
            }

            if (read <= 0) return false;
            var entropy = CalculateEntropy(buffer, read);
            return entropy > 7.0;
        }
        catch
        {
            return false;
        }
    }

    private static double CalculateEntropy(byte[] data, int length)
    {
        var freq = new int[256];
        for (var i = 0; i < length; i++) freq[data[i]]++;

        double entropy = 0;
        for (var i = 0; i < 256; i++)
        {
            if (freq[i] > 0)
            {
                var p = (double)freq[i] / length;
                entropy -= p * Math.Log2(p);
            }
        }
        return entropy;
    }

    private bool IsDotNetAssembly(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var header = new byte[64];
            if (fs.Read(header, 0, 64) < 64) return false;
            if (header[0] != (byte)'M' || header[1] != (byte)'Z') return false;

            var peOffset = BitConverter.ToInt32(header, 0x3C);
            if (peOffset <= 0 || peOffset > fs.Length - 24) return false;

            fs.Position = peOffset;
            var pe = new byte[24];
            if (fs.Read(pe, 0, 24) < 24) return false;
            if (pe[0] != (byte)'P' || pe[1] != (byte)'E') return false;

            var optionalHeaderSize = BitConverter.ToUInt16(pe, 20);
            if (optionalHeaderSize < 100) return false;

            var opt = new byte[optionalHeaderSize];
            fs.Position = peOffset + 24;
            if (fs.Read(opt, 0, optionalHeaderSize) < optionalHeaderSize) return false;

            var magic = BitConverter.ToUInt16(opt, 0);
            var dataDirOffset = magic == 0x20b ? 112 : 96; // PE32+ или PE32
            var cliEntryOffset = dataDirOffset + 14 * 8; // DataDirectory[14] = CLI header
            if (cliEntryOffset + 8 > opt.Length) return false;

            var cliRva = BitConverter.ToInt32(opt, cliEntryOffset);
            return cliRva != 0;
        }
        catch
        {
            return false;
        }
    }

    private bool IsSystemProcess(string name, string path, string publisher)
    {
        var systemProcesses = new[] { "system", "registry", "smss", "csrss", "wininit", "winlogon",
            "services", "lsass", "lsm", "svchost", "spoolsv", "taskhost", "taskhostw",
            "dwm", "explorer", "conhost", "fontdrvhost", "sihost", "startmenuexperiencehost",
            "textinputhost", "searchindexer", "searchprotocolhost", "searchfilterhost",
            "runtimebroker", "shellexperiencehost", "applicationframehost" };

        if (systemProcesses.Contains(name.ToLowerInvariant())) return true;

        var lowerPath = path.ToLowerInvariant();
        var systemPaths = new[] { @"c:\windows\system32\", @"c:\windows\syswow64\", @"c:\windows\winsxs\" };
        if (systemPaths.Any(p => lowerPath.StartsWith(p))) return true;

        return IsMicrosoftPublisher(publisher);
    }

    private bool IsMicrosoftPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var lower = publisher.ToLowerInvariant();
        return lower.Contains("microsoft") || lower.Contains("windows publisher") || lower.Contains("windows");
    }
}
