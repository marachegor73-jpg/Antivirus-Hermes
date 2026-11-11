using System.Collections.Concurrent;

namespace Hermes.Core.Security;

/// <summary>Post-download checking while HERMES is running; not a browser/network blocker.</summary>
public sealed class DownloadMonitor : IDisposable
{
    private readonly DefenderService _defender;
    private readonly string _directory;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<string, byte> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _workers = new(1, 1);
    private FileSystemWatcher? _watcher;
    private bool _disposed;
    public event EventHandler<ScanResult>? ScanCompleted;
    public event EventHandler<string>? MonitoringError;

    public DownloadMonitor(DefenderService defender, string downloadsPath)
    { _defender = defender; _directory = Path.GetFullPath(downloadsPath); }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_watcher is not null) return;
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Наблюдение за загрузками доступно только в Windows.");
        if (!Directory.Exists(_directory)) throw new DirectoryNotFoundException("Папка загрузок не найдена: " + _directory);
        var watcher = new FileSystemWatcher(_directory)
        { IncludeSubdirectories = false, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size, InternalBufferSize = 32 * 1024 };
        watcher.Created += OnFile;
        watcher.Changed += OnFile;
        watcher.Renamed += OnRenamed;
        watcher.Error += (_, e) => MonitoringError?.Invoke(this, "Наблюдение за загрузками пропустило события: " + e.GetException().Message);
        _watcher = watcher;
        watcher.EnableRaisingEvents = true;
    }

    private void OnFile(object sender, FileSystemEventArgs e) => Queue(e.FullPath);
    private void OnRenamed(object sender, RenamedEventArgs e) => Queue(e.FullPath);

    private void Queue(string path)
    {
        if (_stop.IsCancellationRequested || IsPartial(path) || Directory.Exists(path)) return;
        if (_pending.Count >= 100)
        { MonitoringError?.Invoke(this, "Очередь загрузок переполнена. Запустите проверку папки вручную."); return; }
        if (!_pending.TryAdd(path, 0)) return;
        _ = CheckAsync(path);
    }

    private async Task CheckAsync(string path)
    {
        var entered = false;
        FileStream? stableFile = null;
        try
        {
            await _workers.WaitAsync(_stop.Token);
            entered = true;
            // Wait for a stable, unlocked file. Never inspect browser partial-download files.
            long previousSize = -1;
            DateTime previousWrite = DateTime.MinValue;
            var stable = 0;
            var ready = false;
            for (var attempt = 0; attempt < 60; attempt++)
            {
                await Task.Delay(TimeSpan.FromSeconds(2), _stop.Token);
                if (!File.Exists(path)) return;
                var info = new FileInfo(path);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) return;
                if (info.Length == previousSize && info.LastWriteTimeUtc == previousWrite) stable++;
                else stable = 0;
                previousSize = info.Length;
                previousWrite = info.LastWriteTimeUtc;
                if (stable < 2) continue;
                try
                {
                    // Keep writers/renames blocked through the scan: a Changed event while
                    // this path is already pending must not leave newer, unscanned bytes behind.
                    stableFile = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    ready = true;
                    break;
                }
                catch (IOException) { }
            }
            if (!ready)
            {
                ScanCompleted?.Invoke(this, new(path, ScanOutcome.Failed, "Загрузка ещё изменяется или занята. Проверьте файл вручную после завершения загрузки."));
                return;
            }
            var result = await _defender.ScanAsync(path, _stop.Token);
            if (!_stop.IsCancellationRequested) ScanCompleted?.Invoke(this, result);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { if (!_stop.IsCancellationRequested) ScanCompleted?.Invoke(this, new(path, ScanOutcome.Failed, "Не удалось проверить загрузку: " + ex.Message)); }
        finally
        {
            _pending.TryRemove(path, out _);
            // Release only after dequeueing so subsequent modifications enqueue a fresh check.
            stableFile?.Dispose();
            if (entered) _workers.Release();
        }
    }

    private static bool IsPartial(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".crdownload", StringComparison.OrdinalIgnoreCase) || extension.Equals(".part", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".tmp", StringComparison.OrdinalIgnoreCase) || extension.Equals(".download", StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _watcher?.Dispose();
        _stop.Cancel();
        // Existing worker tasks observe cancellation; do not dispose their synchronization primitives underneath them.
    }
}
