using Hermes.Core.Maintenance;
using Hermes.Core.Security;

var failures = 0;
var skipped = 0;
await Check("Cleanup preview includes old cache and preserves fresh data", async () =>
{
    using var fixture = new CacheFixture();
    var oldFile = fixture.Write("cache/old.cache", "old cache", ageHours: 48);
    var freshFile = fixture.Write("cache/fresh.cache", "active cache", ageHours: 1);
    var service = fixture.Service();
    var result = await service.ScanAsync();
    Require(result.Files.Count == 1 && result.Files[0].Path == oldFile, "Preview must contain only the old cache file.");
    Require(File.Exists(oldFile) && File.Exists(freshFile), "Preview must not delete files.");
    Require(result.Files[0].Length == new FileInfo(oldFile).Length, "Preview must report actual size.");
});

await Check("Cleanup rejects files changed after preview", async () =>
{
    using var fixture = new CacheFixture();
    var oldFile = fixture.Write("cache/old.cache", "old cache", ageHours: 48);
    var service = fixture.Service();
    var preview = await service.ScanAsync();
    File.WriteAllText(oldFile, "new important content written after the preview");
    var result = await service.DeleteAsync(preview.Files);
    Require(result.DeletedCount == 0 && result.Errors.Count == 1, "Changed files must not be deleted.");
    Require(File.ReadAllText(oldFile).Contains("important"), "Changed data must remain intact.");
});

await Check("Cleanup rejects paths outside the approved cache root", async () =>
{
    using var fixture = new CacheFixture();
    var outside = fixture.Write("documents/keep.txt", "personal document", ageHours: 48);
    var info = new FileInfo(outside);
    var candidate = new CleanupFile(outside, "forged cache category", info.Length, info.LastWriteTimeUtc);
    var result = await fixture.Service().DeleteAsync([candidate]);
    Require(result.DeletedCount == 0 && result.Errors.Count == 1, "Category text must not authorize deletion.");
    Require(File.ReadAllText(outside) == "personal document", "Files outside the cache must remain intact.");
});

await Check("Cleanup rejects a sibling path with matching root prefix", async () =>
{
    using var fixture = new CacheFixture();
    var outside = fixture.Write("cache-personal/keep.txt", "personal document", ageHours: 48);
    var info = new FileInfo(outside);
    var result = await fixture.Service().DeleteAsync([new CleanupFile(outside, "cache", info.Length, info.LastWriteTimeUtc)]);
    Require(result.DeletedCount == 0 && result.Errors.Count == 1 && File.Exists(outside), "A matching path prefix is not a descendant relationship.");
});

await Check("Cleanup ignores directory links outside cache", async () =>
{
    using var fixture = new CacheFixture();
    var outside = fixture.Write("documents/keep.txt", "personal document", ageHours: 48);
    var link = Path.Combine(fixture.CachePath, "linked-documents");
    if (!TryDirectoryLink(link, Path.GetDirectoryName(outside)!)) return;
    var result = await fixture.Service().ScanAsync();
    Require(result.Files.Count == 0, "Directory links must not be traversed.");
    Require(File.Exists(outside), "The link target must not change.");
});

await Check("Cleanup rejects a cache root replaced by a link after preview", async () =>
{
    using var fixture = new CacheFixture();
    var oldFile = fixture.Write("cache/old.cache", "original", ageHours: 48);
    var service = fixture.Service();
    var preview = await service.ScanAsync();
    var outside = fixture.Write("documents/old.cache", "outside!", ageHours: 48);
    File.SetLastWriteTimeUtc(outside, preview.Files.Single().LastWriteUtc);
    File.Delete(oldFile);
    Directory.Delete(fixture.CachePath);
    if (!TryDirectoryLink(fixture.CachePath, Path.GetDirectoryName(outside)!)) return;
    var result = await service.DeleteAsync(preview.Files);
    Require(result.DeletedCount == 0 && result.Errors.Count == 1, "A replaced root must invalidate the preview.");
    Require(File.ReadAllText(outside) == "outside!", "A link must not redirect deletion to personal files.");
});

await Check("Cleanup honors cancellation", async () =>
{
    using var fixture = new CacheFixture();
    fixture.Write("cache/old.cache", "old cache", ageHours: 48);
    using var cancellation = new CancellationTokenSource();
    cancellation.Cancel();
    try { await fixture.Service().ScanAsync(cancellation.Token); }
    catch (OperationCanceledException) { return; }
    throw new Exception("A cancelled scan must stop.");
});

await Check("Cleanup deletes only a reviewed unchanged file on Windows", async () =>
{
    using var fixture = new CacheFixture();
    var oldFile = fixture.Write("cache/old.cache", "old cache", ageHours: 48);
    var freshFile = fixture.Write("cache/fresh.cache", "active cache", ageHours: 1);
    var service = fixture.Service();
    var preview = await service.ScanAsync();
    var result = await service.DeleteAsync(preview.Files);
    if (OperatingSystem.IsWindows())
        Require(result.DeletedCount == 1 && result.Errors.Count == 0 && !File.Exists(oldFile), "A valid selected file must be deleted on Windows.");
    else
        Require(result.DeletedCount == 0 && result.Errors.Count == 1 && File.Exists(oldFile), "Deletion must fail closed on unsupported platforms.");
    Require(File.Exists(freshFile), "A file omitted from preview must not be deleted.");
});

await Check("Unavailable Defender cannot report a clean scan", async () =>
{
    var scanner = new DefenderService();
    if (OperatingSystem.IsWindows())
    {
        var result = await scanner.ScanAsync(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "missing.exe"));
        Require(result.Outcome == ScanOutcome.Failed, "A missing input must be a scan failure.");
    }
    else
    {
        var status = await scanner.GetStatusAsync();
        Require(!status.Available, "Defender must be unavailable on non-Windows systems.");
        var result = await scanner.ScanAsync(Path.GetTempPath());
        Require(result.Outcome == ScanOutcome.Failed, "An unsupported scan must never claim success.");
    }
});

await Check("A forged process selection cannot terminate HERMES itself", async () =>
{
    using var current = System.Diagnostics.Process.GetCurrentProcess();
    var forged = new ProcessEntry(current.Id, current.ProcessName, 0, current.StartTime.ToUniversalTime(), true, "");
    var result = await new ProcessService().StopAsync(forged, force: true);
    Require(!result.Success, "The actual process must be revalidated instead of trusting CanStop from a stale or forged selection.");
});

await Check("A stale process snapshot is rejected", async () =>
{
    using var current = System.Diagnostics.Process.GetCurrentProcess();
    var stale = new ProcessEntry(current.Id, current.ProcessName, 0, DateTime.UtcNow.AddYears(-1), true, "");
    var result = await new ProcessService().StopAsync(stale, force: true);
    Require(!result.Success, "A reused PID must not authorize an operation on a different process.");
});

await Check("Defender distinguishes ambiguous, failed and confirmed threat results", () =>
{
    Require(DefenderService.ClassifyOutcome(2, "Scan finished with return code 2") == ScanOutcome.AttentionRequired,
        "Exit code 2 alone cannot prove infection or safety.");
    Require(DefenderService.ClassifyOutcome(1, "Scan failed") == ScanOutcome.Failed,
        "A failed scan must never be reported as clean.");
    Require(DefenderService.ClassifyOutcome(0, "Scan finished successfully") == ScanOutcome.Clean,
        "A successful scan without threat evidence should complete normally.");
    Require(DefenderService.ClassifyOutcome(2, "Threat Name : Trojan:Win32/Test") == ScanOutcome.ThreatDetected,
        "Explicit English threat evidence should be reported.");
    Require(DefenderService.ClassifyOutcome(2, "Имя угрозы: Test") == ScanOutcome.ThreatDetected,
        "Explicit Russian threat evidence should be reported.");
    return Task.CompletedTask;
});

await Check("Windows quarantine roundtrip restores exact benign file content", async () =>
{
    OnlyWindows();
    using var fixture = new CacheFixture();
    var path = fixture.Write("cache/benign-roundtrip.txt", "HERMES harmless integration fixture: Привет, мир.", ageHours: 1);
    var expectedBytes = await File.ReadAllBytesAsync(path);
    var expectedHash = await QuarantineService.GetSha256Async(path);
    var service = new QuarantineService();
    QuarantineEntry? entry = null;
    try
    {
        entry = await service.QuarantineAsync(path, expectedHash);
        Require(!File.Exists(path), "A quarantined source must be removed only after durable encrypted storage.");
        Require(entry.Sha256 == expectedHash && entry.Size == expectedBytes.Length, "Quarantine metadata must match the approved file.");
        Require(service.ListEntries().Any(item => item.Id == entry.Id), "The saved quarantine entry must be discoverable.");
        await service.RestoreAsync(entry.Id);
        Require((await File.ReadAllBytesAsync(path)).AsSpan().SequenceEqual(expectedBytes), "Restoring must preserve every byte.");
        Require(!service.ListEntries().Any(item => item.Id == entry.Id), "A restored entry must no longer remain in quarantine.");
    }
    finally
    {
        if (entry is not null && !File.Exists(path) && service.ListEntries().Any(item => item.Id == entry.Id))
            await service.RestoreAsync(entry.Id);
    }
});

await Check("Windows quarantine rejects a file changed after hash approval", async () =>
{
    OnlyWindows();
    using var fixture = new CacheFixture();
    var path = fixture.Write("cache/benign-hash.txt", "content approved before change", ageHours: 1);
    var approvedHash = await QuarantineService.GetSha256Async(path);
    const string changedContent = "new content must never be removed under the old approval";
    await File.WriteAllTextAsync(path, changedContent);
    var service = new QuarantineService();
    var previousEntries = service.ListEntries().Select(item => item.Id).ToHashSet();
    await ExpectThrows<IOException>(() => service.QuarantineAsync(path, approvedHash));
    Require(await File.ReadAllTextAsync(path) == changedContent, "Hash mismatch must preserve the changed source.");
    Require(service.ListEntries().All(item => previousEntries.Contains(item.Id)), "A failed quarantine must not leave a new entry.");
});

await Check("Windows quarantine restore refuses to overwrite a new file", async () =>
{
    OnlyWindows();
    using var fixture = new CacheFixture();
    const string original = "original harmless content";
    const string replacement = "new user content that must not be overwritten";
    var path = fixture.Write("cache/benign-restore.txt", original, ageHours: 1);
    var service = new QuarantineService();
    var entry = await service.QuarantineAsync(path, await QuarantineService.GetSha256Async(path));
    try
    {
        await File.WriteAllTextAsync(path, replacement);
        await ExpectThrows<IOException>(() => service.RestoreAsync(entry.Id));
        Require(await File.ReadAllTextAsync(path) == replacement, "Restore must not overwrite newly created user content.");
        Require(service.ListEntries().Any(item => item.Id == entry.Id), "A refused restore must keep the encrypted original recoverable.");
        File.Delete(path); // Only this test's own replacement, inside its unique temporary fixture.
        await service.RestoreAsync(entry.Id);
        Require(await File.ReadAllTextAsync(path) == original, "Original content must remain recoverable after an overwrite refusal.");
    }
    finally
    {
        if (service.ListEntries().Any(item => item.Id == entry.Id))
        {
            if (File.Exists(path)) File.Delete(path); // Only this fixture's explicitly created file.
            await service.RestoreAsync(entry.Id);
        }
    }
});

Console.WriteLine(failures == 0 ? $"All safety checks passed ({skipped} skipped)." : $"{failures} safety check(s) failed.");
return failures == 0 ? 0 : 1;

async Task Check(string name, Func<Task> test)
{
    try { await test(); Console.WriteLine($"PASS {name}"); }
    catch (TestSkippedException ex) { skipped++; Console.WriteLine($"SKIP {name}: {ex.Message}"); }
    catch (Exception ex) { failures++; Console.Error.WriteLine($"FAIL {name}: {ex.Message}"); }
}

static void OnlyWindows()
{
    if (!OperatingSystem.IsWindows()) throw new TestSkippedException("Requires native Windows file handles and DPAPI.");
}

static async Task ExpectThrows<TException>(Func<Task> action) where TException : Exception
{
    try { await action(); }
    catch (TException) { return; }
    throw new Exception($"Expected {typeof(TException).Name}.");
}

static void Require(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

static bool TryDirectoryLink(string link, string target)
{
    try { Directory.CreateSymbolicLink(link, target); return true; }
    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
    {
        Console.WriteLine($"SKIP symlink scenario: platform does not permit symbolic links ({ex.GetType().Name}).");
        return false;
    }
}

sealed class TestSkippedException(string message) : Exception(message);

sealed class CacheFixture : IDisposable
{
    public string RootPath { get; } = Path.Combine(
        OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
            : Path.GetTempPath(),
        "hermes-safety-" + Guid.NewGuid().ToString("N"));
    public string CachePath => Path.Combine(RootPath, "cache");
    private readonly DateTime now = DateTime.UtcNow;

    public CacheFixture() => Directory.CreateDirectory(CachePath);

    public CleanupService Service() => new([new CleanupRoot(CachePath, "Fixture cache")], () => now);

    public string Write(string relativePath, string content, int ageHours)
    {
        var path = Path.Combine(RootPath, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        File.SetLastWriteTimeUtc(path, now.AddHours(-ageHours));
        return path;
    }

    public void Dispose()
    {
        // Remove links without ever traversing their targets during test cleanup.
        if (!Directory.Exists(RootPath)) return;
        foreach (var entry in Directory.GetFileSystemEntries(RootPath)) Remove(entry);
        Directory.Delete(RootPath);
    }

    private static void Remove(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.Directory) != 0)
        {
            if ((attributes & FileAttributes.ReparsePoint) == 0)
                foreach (var child in Directory.GetFileSystemEntries(path)) Remove(child);
            Directory.Delete(path);
        }
        else File.Delete(path);
    }
}
