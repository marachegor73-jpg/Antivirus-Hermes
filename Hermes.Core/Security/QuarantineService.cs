using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Hermes.Core.Security;

public sealed record QuarantineEntry(string Id, string OriginalPath, string Sha256, long Size, DateTimeOffset QuarantinedAt);

/// <summary>
/// Explicit user-initiated quarantine only. Content is encrypted with AES-GCM;
/// the encryption key is bound to the current Windows user with DPAPI.
/// </summary>
public sealed class QuarantineService
{
    private const long MaximumSize = 256L * 1024 * 1024;
    private readonly string _store;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public QuarantineService()
    {
        _store = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HERMES", "Quarantine");
    }

    public IReadOnlyList<QuarantineEntry> ListEntries()
    {
        if (!Directory.Exists(_store)) return Array.Empty<QuarantineEntry>();
        EnsureNoReparsePoints(_store);
        var entries = new List<QuarantineEntry>();
        foreach (var path in Directory.EnumerateFiles(_store, "*.json"))
        {
            try
            {
                EnsureNoReparsePoints(path);
                var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(path));
                if (entry is not null && IsValidId(entry.Id) && Path.GetFileNameWithoutExtension(path) == entry.Id
                    && File.Exists(Path.Combine(_store, entry.Id + ".bin"))) entries.Add(entry);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { }
        }
        return entries.OrderByDescending(e => e.QuarantinedAt).ToArray();
    }

    public static async Task<string> GetSha256Async(string path, CancellationToken cancellationToken = default)
    {
        EnsureNoReparsePoints(Path.GetFullPath(path));
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken));
    }

    public async Task<QuarantineEntry> QuarantineAsync(string path, string expectedSha256, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Карантин доступен только в Windows.");
        if (expectedSha256.Length != 64 || !expectedSha256.All(Uri.IsHexDigit)) throw new ArgumentException("Необходим SHA-256 выбранного файла.", nameof(expectedSha256));
        var fullPath = Path.GetFullPath(path);
        ValidateSourcePath(fullPath);
        await _gate.WaitAsync(cancellationToken);
        string? blobPath = null, metadataPath = null;
        var sourceRemoved = false;
        byte[]? plain = null, key = null;
        try
        {
            PrepareStore();
            // Hold READ + DELETE with share-read only: writers and renames are blocked while
            // the selected bytes are captured and deleted by handle, avoiding path-swap deletion.
            using var handle = NativeMethods.CreateFile(fullPath, 0x80000000 | 0x00010000,
                0x00000001, IntPtr.Zero, 3, 0x00200000 | 0x08000000, IntPtr.Zero);
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось заблокировать выбранный файл.");
            if (!NativeMethods.GetFileInformationByHandle(handle, out var fileInfo)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((fileInfo.FileAttributes & (uint)(FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 || fileInfo.NumberOfLinks != 1)
                throw new IOException("Карантин не принимает ссылки, папки и файлы с несколькими жёсткими ссылками.");
            VerifyHandlePath(handle, fullPath);
            using var source = new FileStream(handle, FileAccess.Read, 81920, isAsync: false);
            if (source.Length > MaximumSize) throw new IOException("Файл больше 256 МБ. Для него используйте интерфейс безопасности Windows.");
            plain = new byte[checked((int)source.Length)];
            await source.ReadExactlyAsync(plain, cancellationToken);
            var sha256 = Convert.ToHexString(SHA256.HashData(plain));
            if (!sha256.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Файл изменился после выбора. Проверьте и подтвердите его заново.");
            key = GetStoreKey();
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var cipher = new byte[plain.Length];
            var entry = new QuarantineEntry(Guid.NewGuid().ToString("N"), fullPath, sha256, plain.LongLength, DateTimeOffset.UtcNow);
            using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plain, cipher, tag, JsonSerializer.SerializeToUtf8Bytes(entry));
            blobPath = Path.Combine(_store, entry.Id + ".bin");
            metadataPath = Path.Combine(_store, entry.Id + ".json");
            await using (var destination = new FileStream(blobPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await destination.WriteAsync(nonce, cancellationToken);
                await destination.WriteAsync(tag, cancellationToken);
                await destination.WriteAsync(cipher, cancellationToken);
                await destination.FlushAsync(cancellationToken);
                destination.Flush(flushToDisk: true);
            }
            await using (var metadata = new FileStream(metadataPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(metadata, entry, cancellationToken: cancellationToken);
                await metadata.FlushAsync(cancellationToken);
                metadata.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            var disposition = new NativeMethods.FileDispositionInfo { DeleteFile = true };
            if (!NativeMethods.SetFileInformationByHandle(handle, 4, ref disposition, 1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось переместить файл в карантин; исходный файл сохранён.");
            // The original is deleted when this handle closes, after durable encrypted storage.
            sourceRemoved = true;
            source.Dispose();
            return entry;
        }
        finally
        {
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (!sourceRemoved)
            {
                TryDeleteStoreFile(metadataPath);
                TryDeleteStoreFile(blobPath);
            }
            _gate.Release();
        }
    }

    public async Task<QuarantineEntry> RestoreAsync(string id, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Восстановление доступно только в Windows.");
        if (!IsValidId(id)) throw new ArgumentException("Недопустимый идентификатор карантина.", nameof(id));
        await _gate.WaitAsync(cancellationToken);
        byte[]? plain = null, key = null;
        try
        {
            PrepareStore();
            var metadataPath = Path.Combine(_store, id + ".json");
            var blobPath = Path.Combine(_store, id + ".bin");
            EnsureNoReparsePoints(metadataPath);
            EnsureNoReparsePoints(blobPath);
            var entry = JsonSerializer.Deserialize<QuarantineEntry>(await File.ReadAllTextAsync(metadataPath, cancellationToken))
                ?? throw new IOException("Метаданные карантина повреждены.");
            if (entry.Id != id || entry.Size < 0 || entry.Size > MaximumSize) throw new IOException("Метаданные карантина повреждены.");
            var target = Path.GetFullPath(entry.OriginalPath);
            ValidateSourcePath(target);
            if (File.Exists(target) || Directory.Exists(target)) throw new IOException("По исходному пути уже существует файл. Перезапись запрещена.");
            if (!Directory.Exists(Path.GetDirectoryName(target))) throw new DirectoryNotFoundException("Исходная папка отсутствует. Восстановите папку перед восстановлением файла.");
            var length = new FileInfo(blobPath).Length;
            if (length != entry.Size + 28) throw new IOException("Зашифрованный файл повреждён.");
            var encrypted = await File.ReadAllBytesAsync(blobPath, cancellationToken);
            plain = new byte[checked((int)entry.Size)];
            key = GetStoreKey();
            using (var aes = new AesGcm(key, 16)) aes.Decrypt(encrypted.AsSpan(0, 12), encrypted.AsSpan(28), encrypted.AsSpan(12, 16), plain, JsonSerializer.SerializeToUtf8Bytes(entry));
            if (!Convert.ToHexString(SHA256.HashData(plain)).Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("Контрольная сумма карантина не совпадает.");
            EnsureNoReparsePoints(target);
            using (var targetHandle = NativeMethods.CreateFile(target, 0x40000000 | 0x00010000,
                0, IntPtr.Zero, 1, 0x00200000 | 0x80000000, IntPtr.Zero))
            {
                if (targetHandle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось создать файл; перезапись запрещена.");
                try
                {
                    VerifyHandlePath(targetHandle, target);
                    using var destination = new FileStream(targetHandle, FileAccess.Write, 81920, isAsync: false);
                    try
                    {
                        await destination.WriteAsync(plain, cancellationToken);
                        await destination.FlushAsync(cancellationToken);
                        destination.Flush(flushToDisk: true);
                    }
                    catch
                    {
                        var removePartial = new NativeMethods.FileDispositionInfo { DeleteFile = true };
                        NativeMethods.SetFileInformationByHandle(targetHandle, 4, ref removePartial, 1);
                        throw;
                    }
                }
                catch
                {
                    if (!targetHandle.IsClosed)
                    {
                        var removePartial = new NativeMethods.FileDispositionInfo { DeleteFile = true };
                        NativeMethods.SetFileInformationByHandle(targetHandle, 4, ref removePartial, 1);
                    }
                    throw;
                }
            }
            TryDeleteStoreFile(metadataPath);
            TryDeleteStoreFile(blobPath);
            return entry;
        }
        finally
        {
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            _gate.Release();
        }
    }

    private void VerifyHandlePath(SafeFileHandle handle, string expectedPath)
    {
        var resolvedBuffer = new StringBuilder(32768);
        var resolvedLength = NativeMethods.GetFinalPathNameByHandle(handle, resolvedBuffer, (uint)resolvedBuffer.Capacity, 0);
        if (resolvedLength == 0 || resolvedLength >= resolvedBuffer.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось проверить действительный путь файла.");
        var resolvedPath = resolvedBuffer.ToString();
        if (resolvedPath.StartsWith(@"\\?\", StringComparison.Ordinal)) resolvedPath = resolvedPath[4..];
        ValidateSourcePath(resolvedPath);
        if (!resolvedPath.Equals(expectedPath, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Путь файла изменился или содержит перенаправление. Действие отменено.");
    }

    private void PrepareStore()
    {
        EnsureNoReparsePoints(_store);
        Directory.CreateDirectory(_store);
        EnsureNoReparsePoints(_store);
    }

    private byte[] GetStoreKey()
    {
        var keyPath = Path.Combine(_store, "key.dpapi");
        EnsureNoReparsePoints(keyPath);
        if (File.Exists(keyPath))
        {
            var key = Protect(File.ReadAllBytes(keyPath), decrypt: true);
            if (key.Length != 32) throw new CryptographicException("Ключ карантина повреждён.");
            return key;
        }
        var fresh = RandomNumberGenerator.GetBytes(32);
        var temporary = Path.Combine(_store, Guid.NewGuid().ToString("N") + ".keytmp");
        try
        {
            var protectedKey = Protect(fresh, decrypt: false);
            using (var keyFile = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 4096, FileOptions.WriteThrough))
            {
                keyFile.Write(protectedKey);
                // The encrypted payload is recoverable only if its user-bound key is durable too.
                keyFile.Flush(flushToDisk: true);
            }
            try { File.Move(temporary, keyPath, overwrite: false); return fresh; }
            catch (IOException) when (File.Exists(keyPath))
            {
                CryptographicOperations.ZeroMemory(fresh);
                var existing = Protect(File.ReadAllBytes(keyPath), decrypt: true);
                if (existing.Length != 32) throw new CryptographicException("Ключ карантина повреждён.");
                return existing;
            }
        }
        catch { CryptographicOperations.ZeroMemory(fresh); throw; }
        finally { TryDeleteStoreFile(temporary); }
    }

    private void ValidateSourcePath(string fullPath)
    {
        EnsureNoReparsePoints(fullPath);
        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal) || fullPath.IndexOf(':', 2) >= 0)
            throw new IOException("Карантин поддерживает обычные файлы на локальном диске, без альтернативных потоков.");
        foreach (var protectedRoot in new[] {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), _store })
        {
            if (string.IsNullOrWhiteSpace(protectedRoot)) continue;
            var root = Path.GetFullPath(protectedRoot).TrimEnd(Path.DirectorySeparatorChar);
            if (fullPath.Equals(root, StringComparison.OrdinalIgnoreCase) || fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Защищённая системная папка или папка HERMES. Используйте безопасность Windows для обработки этого файла.");
        }
        if (Environment.ProcessPath is { } executable && fullPath.Equals(Path.GetFullPath(executable), StringComparison.OrdinalIgnoreCase))
            throw new IOException("Исполняемый файл HERMES нельзя перемещать в собственный карантин.");
    }

    private static void EnsureNoReparsePoints(string path)
    {
        var current = Path.GetFullPath(path);
        while (!string.IsNullOrEmpty(current))
        {
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Операция со ссылками и точками повторной обработки запрещена: " + current);
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            var parent = Path.GetDirectoryName(current);
            if (parent == current) break;
            current = parent;
        }
    }

    private static bool IsValidId(string id) => Guid.TryParseExact(id, "N", out _);
    private static void TryDeleteStoreFile(string? path)
    {
        if (path is null) return;
        try { File.Delete(path); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static byte[] Protect(byte[] bytes, bool decrypt)
    {
        var inputPointer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, inputPointer, bytes.Length);
            var input = new NativeMethods.DataBlob { Size = bytes.Length, Data = inputPointer };
            NativeMethods.DataBlob output;
            var success = decrypt
                ? NativeMethods.CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : NativeMethods.CryptProtectData(ref input, "HERMES quarantine key", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!success) throw new CryptographicException(Marshal.GetLastWin32Error());
            try
            {
                var result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, result.Length);
                return result;
            }
            finally { NativeMethods.LocalFree(output.Data); }
        }
        finally
        {
            for (var index = 0; index < bytes.Length; index++) Marshal.WriteByte(inputPointer, index, 0);
            Marshal.FreeHGlobal(inputPointer);
        }
    }

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)] internal struct DataBlob { internal int Size; internal IntPtr Data; }
        [StructLayout(LayoutKind.Sequential)] internal struct FileDispositionInfo { [MarshalAs(UnmanagedType.U1)] internal bool DeleteFile; }
        [StructLayout(LayoutKind.Sequential)] internal struct ByHandleFileInformation
        {
            internal uint FileAttributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
            internal uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(string path, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint size, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass, ref FileDispositionInfo information, uint size);
        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptProtectData(ref DataBlob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);
        [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);
        [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);
    }
}
