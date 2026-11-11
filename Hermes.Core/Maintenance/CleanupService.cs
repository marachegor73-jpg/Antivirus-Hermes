using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

[assembly: InternalsVisibleTo("Hermes.Tests")]

namespace Hermes.Core.Maintenance;

public sealed record CleanupFile(string Path, string Category, long Length, DateTime LastWriteUtc);
public sealed record CleanupScanResult(IReadOnlyList<CleanupFile> Files, int SkippedCount, bool LimitReached);
public sealed record CleanupDeleteResult(int DeletedCount, long FreedBytes, IReadOnlyList<string> Errors);
internal sealed record CleanupRoot(string Path, string Category);

/// <summary>Previews old cache files. Deletion must be requested explicitly by the caller after consent.</summary>
public sealed class CleanupService
{
    private const int MaximumFiles = 50_000;
    private readonly IReadOnlyList<CleanupRoot> roots;
    private readonly Func<DateTime> utcNow;
    private readonly string applicationDirectory = Normalize(AppContext.BaseDirectory);
    private readonly string quarantineDirectory = Normalize(System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HERMES"));

    public CleanupService() : this(GetDefaultRoots()) { }

    internal CleanupService(IEnumerable<CleanupRoot> roots, Func<DateTime>? utcNow = null)
    {
        this.roots = roots.Select(root => new CleanupRoot(Normalize(root.Path), root.Category))
            .Where(root => !string.IsNullOrWhiteSpace(root.Path))
            .DistinctBy(root => root.Path, StringComparer.OrdinalIgnoreCase).ToArray();
        this.utcNow = utcNow ?? (() => DateTime.UtcNow);
    }

    public Task<CleanupScanResult> ScanAsync(CancellationToken cancellationToken = default) => Task.Run(() =>
    {
        var files = new List<CleanupFile>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skipped = 0;
        var cutoff = utcNow().AddHours(-24);
        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Directory.Exists(root.Path)) continue;
            if (!HasNoReparseAncestors(root.Path)) { skipped++; continue; }
            var directories = new Stack<string>();
            directories.Push(root.Path);
            while (directories.TryPop(out var directory))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (Excluded(directory) || !HasNoReparseAncestors(directory)) { skipped++; continue; }
                string[] entries;
                try { entries = Directory.GetFileSystemEntries(directory); }
                catch (Exception ex) when (IsFileError(ex)) { skipped++; continue; }
                foreach (var entry in entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        var attributes = File.GetAttributes(entry);
                        if ((attributes & FileAttributes.ReparsePoint) != 0 || Excluded(entry)) { skipped++; continue; }
                        if ((attributes & FileAttributes.Directory) != 0) { directories.Push(entry); continue; }
                        var info = new FileInfo(entry);
                        if (info.LastWriteTimeUtc >= cutoff || !seen.Add(info.FullName)) continue;
                        files.Add(new CleanupFile(info.FullName, root.Category, info.Length, info.LastWriteTimeUtc));
                        if (files.Count >= MaximumFiles) return new CleanupScanResult(files, skipped, true);
                    }
                    catch (Exception ex) when (IsFileError(ex)) { skipped++; }
                }
            }
        }
        return new CleanupScanResult(files.OrderByDescending(file => file.Length).ToArray(), skipped, false);
    }, cancellationToken);

    public Task<CleanupDeleteResult> DeleteAsync(IEnumerable<CleanupFile> selected,
        CancellationToken cancellationToken = default)
    {
        var snapshot = selected.DistinctBy(file => file.Path, StringComparer.OrdinalIgnoreCase).ToArray();
        return Task.Run(() =>
        {
            var count = 0;
            long bytes = 0;
            var errors = new List<string>();
            foreach (var file in snapshot)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    ValidateCandidate(file);
                    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Удаление доступно только в Windows.");
                    DeleteThroughValidatedHandle(file);
                    count++;
                    bytes += file.Length;
                }
                catch (Exception ex) when (IsFileError(ex) || ex is InvalidOperationException or PlatformNotSupportedException)
                {
                    errors.Add($"{file.Path}: {ex.Message}");
                }
            }
            return new CleanupDeleteResult(count, bytes, errors);
        }, cancellationToken);
    }

    private void ValidateCandidate(CleanupFile file)
    {
        var path = Normalize(file.Path);
        if (!System.IO.Path.IsPathFullyQualified(file.Path) || !roots.Any(root => IsInside(path, root.Path)) || Excluded(path))
            throw new InvalidOperationException("Файл находится вне разрешённых папок кэша.");
        if (!HasNoReparseAncestors(path)) throw new InvalidOperationException("Ссылки и точки повторной обработки пропущены.");
        var info = new FileInfo(path);
        if (!info.Exists || (info.Attributes & FileAttributes.Directory) != 0)
            throw new InvalidOperationException("Файл больше не существует или стал папкой.");
        if (info.Length != file.Length || info.LastWriteTimeUtc != file.LastWriteUtc || info.LastWriteTimeUtc >= utcNow().AddHours(-24))
            throw new InvalidOperationException("Файл изменился после поиска; выполните поиск снова.");
    }

    private static void DeleteThroughValidatedHandle(CleanupFile file)
    {
        // Exclusive access and handle-relative disposition prevent replacing the selected file between validation and deletion.
        using var handle = CreateFileW(file.Path, 0x80000000 | 0x00010000, 0, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (!GetFileInformationByHandle(handle, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var actualLength = ((long)info.FileSizeHigh << 32) | info.FileSizeLow;
        var lastWrite = DateTime.FromFileTimeUtc(((long)info.LastWriteHigh << 32) | info.LastWriteLow);
        if ((info.FileAttributes & ((uint)FileAttributes.Directory | (uint)FileAttributes.ReparsePoint)) != 0 ||
            actualLength != file.Length || lastWrite != file.LastWriteUtc)
            throw new InvalidOperationException("Файл изменился после поиска.");
        var buffer = new StringBuilder(32768);
        var chars = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (chars == 0 || chars >= buffer.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error());
        var finalPath = buffer.ToString();
        if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) finalPath = @"\\" + finalPath[8..];
        else if (finalPath.StartsWith(@"\\?\", StringComparison.Ordinal)) finalPath = finalPath[4..];
        if (!string.Equals(Normalize(finalPath), Normalize(file.Path), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Фактический путь файла изменился; удаление отменено.");
        var disposition = new FileDispositionInfo { DeleteFile = 1 };
        if (!SetFileInformationByHandle(handle, 4, ref disposition, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private bool Excluded(string path) => IsInsideOrEqual(path, quarantineDirectory) || IsInsideOrEqual(path, applicationDirectory);

    private static IEnumerable<CleanupRoot> GetDefaultRoots()
    {
        if (!OperatingSystem.IsWindows()) yield break;
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(local)) yield break;
        yield return new CleanupRoot(System.IO.Path.Combine(local, "Temp"), "Временные файлы Windows");
        foreach (var browser in new[] { ("Google", "Chrome"), ("Microsoft", "Edge") })
        {
            var userData = System.IO.Path.Combine(local, browser.Item1, browser.Item2, "User Data");
            foreach (var profile in SafeDirectories(userData).Where(path =>
                         System.IO.Path.GetFileName(path) == "Default" || System.IO.Path.GetFileName(path).StartsWith("Profile ", StringComparison.Ordinal)))
            {
                yield return new CleanupRoot(System.IO.Path.Combine(profile, "Cache", "Cache_Data"), $"Кэш {browser.Item2}");
                yield return new CleanupRoot(System.IO.Path.Combine(profile, "Code Cache"), $"Кэш {browser.Item2}");
                yield return new CleanupRoot(System.IO.Path.Combine(profile, "GPUCache"), $"Кэш {browser.Item2}");
            }
        }
        foreach (var profile in SafeDirectories(System.IO.Path.Combine(local, "Mozilla", "Firefox", "Profiles")))
            yield return new CleanupRoot(System.IO.Path.Combine(profile, "cache2", "entries"), "Кэш Firefox");
    }

    private static string[] SafeDirectories(string path)
    {
        try { return Directory.Exists(path) && HasNoReparseAncestors(path) ? Directory.GetDirectories(path) : []; }
        catch (Exception ex) when (IsFileError(ex)) { return []; }
    }

    private static bool HasNoReparseAncestors(string path)
    {
        try
        {
            for (var current = Normalize(path); !string.IsNullOrEmpty(current); current = System.IO.Path.GetDirectoryName(current) ?? "")
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return false;
            return true;
        }
        catch (Exception ex) when (IsFileError(ex)) { return false; }
    }

    private static string Normalize(string path) => string.IsNullOrWhiteSpace(path) ? "" : System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(path));
    private static bool IsInside(string path, string root) => !string.IsNullOrEmpty(root) && path.StartsWith(root + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    private static bool IsInsideOrEqual(string path, string root) => !string.IsNullOrEmpty(root) && (string.Equals(path, root, StringComparison.OrdinalIgnoreCase) || IsInside(path, root));
    private static bool IsFileError(Exception ex) => ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or Win32Exception or ArgumentException or NotSupportedException;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes, CreationLow, CreationHigh, AccessLow, AccessHigh, LastWriteLow, LastWriteHigh,
            VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileDispositionInfo { public byte DeleteFile; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass, ref FileDispositionInfo information, uint bufferSize);
}
