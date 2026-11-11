using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Hermes.Core.Maintenance;

public sealed record ProcessEntry(int Id, string Name, long WorkingSetBytes, DateTime StartTimeUtc,
    bool CanStop, string ProtectionReason);
public sealed record ProcessStopResult(bool Success, string Message);

/// <summary>Lists processes without judging whether the user's applications are needed.</summary>
public sealed class ProcessService
{
    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Idle", "System", "Registry", "Memory Compression", "Secure System", "smss", "csrss", "wininit",
        "services", "lsass", "lsaiso", "winlogon", "svchost", "fontdrvhost", "dwm", "sihost", "taskhostw",
        "explorer", "ShellExperienceHost", "StartMenuExperienceHost", "SearchHost", "SearchIndexer", "RuntimeBroker",
        "MsMpEng", "NisSrv", "MpCmdRun", "MpDefenderCoreService", "SecurityHealthService", "SecurityHealthSystray",
        "MsSense", "SenseIR", "SenseNdr", "SenseCE", "SenseSampleUploader", "Hermes", "HERMES",
        "avp", "avpui", "ekrn", "egui", "avastsvc", "avastui", "avgsvc", "avgui", "bdagent", "vsserv",
        "mbamservice", "mbamtray", "nortonsecurity", "ccsvchst", "mcshield", "mfemms", "sophoshealth", "sophossps"
    };

    public Task<IReadOnlyList<ProcessEntry>> GetProcessesAsync(CancellationToken cancellationToken = default) => Task.Run<IReadOnlyList<ProcessEntry>>(() =>
    {
        if (!OperatingSystem.IsWindows()) return [];
        var result = new List<ProcessEntry>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var id = process.Id;
                    var name = process.ProcessName;
                    long memory = 0;
                    try { memory = process.WorkingSet64; } catch (Exception ex) when (IsProcessError(ex)) { }
                    using var handle = OpenProcess(0x1000, false, (uint)id);
                    var start = DateTime.MinValue;
                    if (!handle.IsInvalid && GetProcessTimes(handle, out var created, out _, out _, out _)) start = DateTime.FromFileTimeUtc(created);
                    var reason = GetProtectionReason(process, handle, start);
                    result.Add(new ProcessEntry(id, name, memory, start, reason.Length == 0, reason));
                }
                catch (Exception ex) when (IsProcessError(ex)) { /* Process exited while taking the snapshot. */ }
            }
        }
        return result.OrderByDescending(process => process.WorkingSetBytes).ToArray();
    }, cancellationToken);

    public Task<ProcessStopResult> StopAsync(ProcessEntry entry, bool force = false,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        if (!OperatingSystem.IsWindows()) return new ProcessStopResult(false, "Управление процессами доступно только в Windows.");
        if (!entry.CanStop || entry.StartTimeUtc == DateTime.MinValue) return new ProcessStopResult(false, "Этот процесс защищён от завершения.");
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            // Holding the native handle keeps the original process object alive and prevents PID reuse during this operation.
            using var handle = OpenProcess(0x1000u | (force ? 0x0001u : 0u), false, (uint)entry.Id);
            if (handle.IsInvalid) return new ProcessStopResult(false, "Процесс недоступен или уже завершён.");
            if (!GetProcessTimes(handle, out var created, out _, out _, out _) || DateTime.FromFileTimeUtc(created) != entry.StartTimeUtc)
                return new ProcessStopResult(false, "Список процессов устарел. Обновите его перед завершением.");
            using var process = Process.GetProcessById(entry.Id);
            var reason = GetProtectionReason(process, handle, DateTime.FromFileTimeUtc(created));
            if (reason.Length > 0) return new ProcessStopResult(false, reason);
            if (!string.Equals(process.ProcessName, entry.Name, StringComparison.OrdinalIgnoreCase))
                return new ProcessStopResult(false, "Процесс изменился. Обновите список.");
            cancellationToken.ThrowIfCancellationRequested();
            if (force)
            {
                if (!TerminateProcess(handle, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
                return new ProcessStopResult(true, $"Процесс {entry.Name} завершён принудительно.");
            }
            if (!process.CloseMainWindow())
                return new ProcessStopResult(false, "У процесса нет окна для обычного закрытия. Принудительное завершение требует отдельного подтверждения.");
            var timer = Stopwatch.StartNew();
            while (timer.Elapsed < TimeSpan.FromSeconds(5))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (process.HasExited) return new ProcessStopResult(true, $"Приложение {entry.Name} закрыто.");
                await Task.Delay(150, cancellationToken);
            }
            return new ProcessStopResult(false, "Запрос на закрытие отправлен. Приложение может ожидать сохранения документов; проверьте его окно.");
        }
        catch (Exception ex) when (IsProcessError(ex)) { return new ProcessStopResult(false, ex.Message); }
    }, cancellationToken);

    private static string GetProtectionReason(Process process, SafeProcessHandle handle, DateTime start)
    {
        try
        {
            if (process.Id <= 4 || process.Id == Environment.ProcessId || ProtectedNames.Contains(process.ProcessName))
                return "Системный процесс, служба безопасности или HERMES.";
            if (handle.IsInvalid || start == DateTime.MinValue) return "Не удалось безопасно определить процесс.";
            using var currentProcess = Process.GetCurrentProcess();
            if (process.SessionId != currentProcess.SessionId) return "Процесс другого сеанса Windows.";
            if (!IsProcessCritical(handle, out var critical) || critical) return "Критический или защищённый процесс Windows.";
            if (!OwnedByCurrentUser(handle)) return "Процесс другого пользователя или системной службы.";
            var path = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(path)) return "Не удалось проверить путь приложения.";
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (Inside(path, windows)) return "Компонент Windows.";
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (!Inside(path, profile) && !Inside(path, programFiles) && !Inside(path, programFilesX86))
                return "Приложение вне проверенных пользовательских папок.";
            if (path.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase)) return "Защищённый компонент или служба безопасности.";
            return "";
        }
        catch (Exception ex) when (IsProcessError(ex)) { return "Не удалось проверить владельца и безопасность процесса."; }
    }

    private static bool OwnedByCurrentUser(SafeProcessHandle process)
    {
        using var current = OpenProcess(0x1000, false, (uint)Environment.ProcessId);
        var actual = ReadUserSid(process);
        var expected = ReadUserSid(current);
        return actual is { Length: > 0 } && expected is { Length: > 0 } && actual.AsSpan().SequenceEqual(expected);
    }

    private static byte[]? ReadUserSid(SafeProcessHandle process)
    {
        if (process.IsInvalid || !OpenProcessToken(process, 0x0008, out var token)) return null;
        using (token)
        {
            GetTokenInformation(token, 1, IntPtr.Zero, 0, out var length);
            if (length == 0 || length > 65536) return null;
            var buffer = Marshal.AllocHGlobal((int)length);
            try
            {
                if (!GetTokenInformation(token, 1, buffer, length, out _)) return null;
                var sid = Marshal.ReadIntPtr(buffer);
                var sidLength = GetLengthSid(sid);
                if (sidLength == 0 || sidLength > 1024) return null;
                var bytes = new byte[sidLength];
                Marshal.Copy(sid, bytes, 0, bytes.Length);
                return bytes;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    private static bool Inside(string path, string root) => !string.IsNullOrWhiteSpace(root) &&
        Path.GetFullPath(path).StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    private static bool IsProcessError(Exception ex) => ex is Win32Exception or InvalidOperationException or NotSupportedException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessCritical(SafeProcessHandle process, [MarshalAs(UnmanagedType.Bool)] out bool critical);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, IntPtr information, uint length, out uint required);
    [DllImport("advapi32.dll")]
    private static extern uint GetLengthSid(IntPtr sid);
}
