using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Hermes.Core.Security;

public enum ScanOutcome { Clean, ThreatDetected, AttentionRequired, Failed, Cancelled }

public sealed record DefenderStatus(bool Available, bool RealTimeProtectionEnabled, string Message);

public sealed record ScanResult(string Path, ScanOutcome Outcome, string Details)
{
    public IReadOnlyList<string> ThreatPaths { get; init; } = Array.Empty<string>();
}

/// <summary>Runs the installed Microsoft Defender engine. Never requests remediation.</summary>
public sealed class DefenderService
{
    private static readonly SemaphoreSlim ScanGate = new(1, 1);

    public async Task<DefenderStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return new(false, false, "Проверка Microsoft Defender доступна только в Windows.");
        if (FindDefenderExecutable() is null)
            return new(false, false, "Microsoft Defender не найден. Проверка файлов недоступна.");
        try
        {
            var powershell = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            var result = await RunAsync(powershell,
                ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference='Stop'; Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress"],
                timeout.Token);
            if (result.ExitCode != 0)
                return new(false, false, "Не удалось получить состояние Defender. Возможно, он отключён другой антивирусной программой. " + result.Output);
            using var json = JsonDocument.Parse(result.Output.Trim().TrimStart('\uFEFF'));
            var root = json.RootElement;
            var available = root.GetProperty("AMServiceEnabled").GetBoolean() && root.GetProperty("AntivirusEnabled").GetBoolean();
            var realtime = root.GetProperty("RealTimeProtectionEnabled").GetBoolean();
            return new(available, realtime, available
                ? realtime ? "Microsoft Defender доступен. Защита Windows в реальном времени включена." : "Microsoft Defender доступен. Защита Windows в реальном времени выключена."
                : "Microsoft Defender отключён; HERMES не сможет проверить файлы.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { return new(false, false, "Defender не ответил за 20 секунд. Состояние защиты неизвестно."); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or JsonException or InvalidOperationException or KeyNotFoundException)
        { return new(false, false, "Не удалось получить состояние Defender: " + ex.Message); }
    }

    public async Task<ScanResult> ScanAsync(string path, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return new(path, ScanOutcome.Failed, "Проверка Microsoft Defender доступна только в Windows.");
        string fullPath;
        try { fullPath = System.IO.Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        { return new(path, ScanOutcome.Failed, "Недопустимый путь: " + ex.Message); }
        if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
            return new(fullPath, ScanOutcome.Failed, "Файл или папка не найдены.");
        var executable = FindDefenderExecutable();
        if (executable is null)
            return new(fullPath, ScanOutcome.Failed, "Microsoft Defender не найден. Проверка не выполнена.");
        var entered = false;
        try
        {
            await ScanGate.WaitAsync(cancellationToken);
            entered = true;
            // DisableRemediation is supported only for custom scans (ScanType 3).
            var result = await RunAsync(executable,
                ["-Scan", "-ScanType", "3", "-File", fullPath, "-DisableRemediation"], cancellationToken);
            var paths = ExtractThreatPaths(result.Output, fullPath);
            var outcome = ClassifyOutcome(result.ExitCode, result.Output, paths);
            var prefix = outcome switch
            {
                ScanOutcome.Clean => "Microsoft Defender завершил проверку: угрозы не обнаружены.",
                ScanOutcome.ThreatDetected => "Defender сообщил об угрозе. HERMES не удалял и не перемещал файлы.",
                ScanOutcome.AttentionRequired => "Defender требует внимания (код 2): возможна угроза или ошибка проверки. Изучите отчёт; файл нельзя считать безопасным.",
                _ => $"Проверка не завершена успешно (код {result.ExitCode}). Файл нельзя считать безопасным."
            };
            return new(fullPath, outcome, prefix + Environment.NewLine + Environment.NewLine + result.Output) { ThreatPaths = paths };
        }
        catch (OperationCanceledException)
        { return new(fullPath, ScanOutcome.Cancelled, "Проверка отменена. Результат безопасности неизвестен."); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException)
        { return new(fullPath, ScanOutcome.Failed, "Проверка не выполнена: " + ex.Message); }
        finally { if (entered) ScanGate.Release(); }
    }

    internal static ScanOutcome ClassifyOutcome(int exitCode, string output, IReadOnlyList<string>? threatPaths = null)
    {
        var explicitThreat = Regex.IsMatch(output,
            @"(?im)^\s*(?:Threat\s*(?:Name)?\s*:|Threat\s+detected\b|Угроза\s*(?:обнаружена|:)|Имя\s+угрозы\s*:)");
        // Exit code 2 also covers failures; it is never sufficient proof of infection.
        return threatPaths is { Count: > 0 } || explicitThreat ? ScanOutcome.ThreatDetected
            : exitCode == 0 ? ScanOutcome.Clean
            : exitCode == 2 ? ScanOutcome.AttentionRequired : ScanOutcome.Failed;
    }

    public static string? FindDefenderExecutable()
    {
        if (!OperatingSystem.IsWindows()) return null;
        var platform = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        try
        {
            if (Directory.Exists(platform))
                foreach (var directory in Directory.GetDirectories(platform).OrderByDescending(p => p, StringComparer.OrdinalIgnoreCase))
                {
                    var candidate = System.IO.Path.Combine(directory, "MpCmdRun.exe");
                    if (File.Exists(candidate)) return candidate;
                }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        var fallback = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender", "MpCmdRun.exe");
        return File.Exists(fallback) ? fallback : null;
    }

    private static IReadOnlyList<string> ExtractThreatPaths(string output, string scanPath)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in Regex.Matches(output, @"(?im)\bfile:_?([^\r\n]+)"))
        {
            var value = match.Groups[1].Value.Trim().Trim('"');
            try
            {
                if (!System.IO.Path.IsPathFullyQualified(value)) continue;
                var full = System.IO.Path.GetFullPath(value);
                var scope = scanPath.TrimEnd(System.IO.Path.DirectorySeparatorChar) + System.IO.Path.DirectorySeparatorChar;
                if ((full.Equals(scanPath, StringComparison.OrdinalIgnoreCase) || full.StartsWith(scope, StringComparison.OrdinalIgnoreCase)) && File.Exists(full))
                    paths.Add(full);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { }
        }
        return paths.ToArray();
    }

    private static async Task<(int ExitCode, string Output)> RunAsync(string executable, string[] arguments, CancellationToken cancellationToken)
    {
        var info = new ProcessStartInfo(executable)
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in arguments) info.ArgumentList.Add(arg);
        using var process = new Process { StartInfo = info };
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken);
            return (process.ExitCode, (await stdout + Environment.NewLine + await stderr).Trim());
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            try { await Task.WhenAll(stdout, stderr); } catch (OperationCanceledException) { }
            throw;
        }
    }
}
