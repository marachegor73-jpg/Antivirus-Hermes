using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Hermes.Core.Maintenance;
using Hermes.Core.Security;
using Microsoft.Win32;
using Forms = System.Windows.Forms;

namespace Hermes.Desktop;

public partial class MainWindow : Window
{
    private readonly DefenderService defender = new();
    private readonly CleanupService cleaner = new();
    private readonly ProcessService processes = new();
    private readonly QuarantineService quarantine = new();
    private readonly ObservableCollection<ScanRow> scans = new();
    private readonly ObservableCollection<CleanupRow> rubbish = new();
    private readonly ObservableCollection<ProcessRow> tasks = new();
    private readonly ObservableCollection<VaultRow> vault = new();
    private readonly ObservableCollection<string> activity = new();
    private readonly CancellationTokenSource lifetime = new();
    private CancellationTokenSource? operation;
    private DownloadMonitor? monitor;
    private Forms.NotifyIcon? tray;
    private readonly bool smokeTest;
    private bool busy;
    private bool closing;
    private long freed;
    private readonly string downloads = GetDownloadsFolder();

    public MainWindow() : this(false) { }

    internal MainWindow(bool smokeTest)
    {
        this.smokeTest = smokeTest;
        InitializeComponent();
        ScanGrid.ItemsSource = scans;
        CleanupGrid.ItemsSource = rubbish;
        ProcessGrid.ItemsSource = tasks;
        VaultGrid.ItemsSource = vault;
        ActivityList.ItemsSource = activity;
        DateText.Text = DateTime.Now.ToString("dd MMMM yyyy", CultureInfo.GetCultureInfo("ru-RU")).ToUpperInvariant();
        DownloadPathText.Text = downloads;
        Loaded += OnLoaded;
        Closing += (_, e) => {
            if (busy && !Confirm("Сейчас выполняется операция. Закрыть HERMES и запросить её отмену? Уже выполненные изменения сохранятся."))
            { e.Cancel = true; return; }
            closing = true;
            lifetime.Cancel();
            operation?.Cancel();
            monitor?.Dispose();
            if (tray is not null) { tray.Visible = false; tray.Dispose(); }
        };
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (smokeTest) return;
        AddActivity("HERMES запущен. Изменения — только с подтверждением.");
        RefreshVaultData();
        await Run("Проверка состояния защиты…", async token => {
            var state = await defender.GetStatusAsync(token);
            ProtectionTitle.Text = state.Available
                ? state.RealTimeProtectionEnabled ? "Защита Windows включена" : "Защита в реальном времени выключена"
                : "Проверка защиты недоступна";
            ProtectionDescription.Text = state.Message;
            AddActivity(state.Message);
        });
        if (!closing) WatchCheck.IsChecked = true;
    }

    private void Navigate(object sender, RoutedEventArgs e)
    {
        if (sender is Button button && int.TryParse(button.Tag?.ToString(), out var page))
        {
            Pages.SelectedIndex = page;
            if (page == 4) RefreshVaultData();
        }
    }

    private async Task Run(string text, Func<CancellationToken, Task> action)
    {
        if (busy || closing) return;
        busy = true;
        using var source = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        operation = source;
        SetBusy(true);
        StatusText.Text = text;
        try { await action(source.Token); if (!closing) StatusText.Text = "Операция завершена"; }
        catch (OperationCanceledException) { if (!closing) { StatusText.Text = "Операция остановлена. Уже выполненные изменения сохраняются."; AddActivity(StatusText.Text); } }
        catch (Exception ex) { if (!closing) { StatusText.Text = "Операция не выполнена: " + ex.Message; AddActivity(StatusText.Text); ShowText("Не удалось выполнить операцию", ex.Message); } }
        finally { operation = null; busy = false; if (!closing) SetBusy(false); }
    }

    private void SetBusy(bool value)
    {
        ScanActions.IsEnabled = !value;
        CleanupScanButton.IsEnabled = !value;
        CleanupDeleteButton.IsEnabled = !value;
        ProcessesRefreshButton.IsEnabled = !value;
        ProcessCloseButton.IsEnabled = !value;
        ProcessKillButton.IsEnabled = !value;
        RestoreButton.IsEnabled = !value;
        BusyProgress.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
    }
    private void CancelOperation(object sender, RoutedEventArgs e) => operation?.Cancel();

    private async void ScanFile(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        var dialog = new OpenFileDialog { Title = "HERMES — выбрать файл для проверки", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) await ScanPath(dialog.FileName);
    }
    private async void ScanFolder(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        var dialog = new OpenFolderDialog { Title = "HERMES — выбрать папку", Multiselect = false };
        if (dialog.ShowDialog(this) == true) await ScanPath(dialog.FolderName);
    }
    private async void ScanDownloads(object sender, RoutedEventArgs e) => await ScanPath(downloads);
    private async Task ScanPath(string path)
    {
        await Run("Microsoft Defender проверяет: " + path, async token => {
            string? hash = null;
            if (File.Exists(path))
            {
                try { hash = await QuarantineService.GetSha256Async(path, token); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { AddActivity("Отпечаток файла недоступен: " + ex.Message); }
            }
            var result = await defender.ScanAsync(path, token);
            var row = AddScan(result, hash);
            ScanGrid.SelectedItem = row;
            AddActivity(row.Verdict + " — " + path);
            if (result.Outcome != ScanOutcome.Clean) ShowText(row.Verdict, result.Details);
        });
    }
    private ScanRow AddScan(ScanResult result, string? hash = null)
    {
        var row = new ScanRow(result, hash);
        scans.Insert(0, row);
        if (scans.Count > 500) scans.RemoveAt(scans.Count - 1);
        return row;
    }
    private void ScanDetails(object sender, RoutedEventArgs e)
    {
        if (ScanGrid.SelectedItem is ScanRow row) ShowText(row.Verdict, row.Result.Details);
        else StatusText.Text = "Сначала выбери результат проверки.";
    }
    private void ScanSelectionChanged(object sender, SelectionChangedEventArgs e) { }
    private async void QuarantineSelected(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        if (ScanGrid.SelectedItem is not ScanRow row) { StatusText.Text = "Выбери проверенный файл."; return; }
        if (row.Result.Outcome is not (ScanOutcome.ThreatDetected or ScanOutcome.AttentionRequired))
        { ShowText("Карантин", "Изоляция доступна для файла с обнаруженной угрозой или результатом, требующим внимания."); return; }
        if (row.Hash is null || !File.Exists(row.Path))
        { ShowText("Нужна проверка файла", "Выбери «Проверить файл» и проверь конкретный файл ещё раз. Для папок и результатов фонового наблюдения изоляция недоступна."); return; }
        if (!Confirm("Переместить файл в зашифрованный карантин?\n\n" + row.Path + "\n\nИсходный файл будет удалён только после сохранения копии в карантине.")) return;
        await Run("Изоляция файла…", async token => {
            await quarantine.QuarantineAsync(row.Path, row.Hash, token);
            AddActivity("Файл изолирован по подтверждению: " + row.Path);
            RefreshVaultData();
            ShowText("Файл изолирован", "Копия сохранена в карантине. Восстановление доступно в разделе «Карантин».");
        });
    }

    private void ToggleWatch(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || closing) return;
        monitor?.Dispose();
        monitor = null;
        if (WatchCheck.IsChecked == true)
        {
            try
            {
                monitor = new DownloadMonitor(defender, downloads);
                monitor.ScanCompleted += (_, result) => {
                    if (closing) return;
                    Dispatcher.BeginInvoke(new Action(() => {
                        if (closing) return;
                        var row = AddScan(result);
                        AddActivity("Загрузки: " + row.Verdict + " — " + result.Path);
                        if (result.Outcome != ScanOutcome.Clean && result.Outcome != ScanOutcome.Cancelled)
                        {
                            tray?.ShowBalloonTip(10000, "HERMES — проверь загрузку", Path.GetFileName(result.Path) + ": " + row.Verdict, Forms.ToolTipIcon.Warning);
                            StatusText.Text = "Внимание: новая загрузка требует проверки. Открой раздел «Антивирус».";
                        }
                    }));
                };
                monitor.MonitoringError += (_, message) => {
                    if (!closing) Dispatcher.BeginInvoke(new Action(() => { if (!closing) { AddActivity(message); StatusText.Text = message; } }));
                };
                monitor.Start();
                EnsureTray();
                WatchState.Text = "Наблюдение";
                AddActivity("Включена проверка новых файлов: " + downloads);
            }
            catch (Exception ex)
            {
                monitor?.Dispose(); monitor = null;
                WatchCheck.IsChecked = false;
                WatchState.Text = "Недоступно";
                AddActivity("Наблюдение не запущено: " + ex.Message);
            }
        }
        else { WatchState.Text = "Выключено"; AddActivity("Проверка новых загрузок выключена."); }
    }
    private void EnsureTray()
    {
        if (tray is not null) return;
        tray = new Forms.NotifyIcon { Text = "HERMES — наблюдение за загрузками", Icon = System.Drawing.SystemIcons.Shield, Visible = true };
        tray.BalloonTipClicked += (_, _) => { Show(); WindowState = WindowState.Normal; Activate(); Pages.SelectedIndex = 1; };
        tray.DoubleClick += (_, _) => { Show(); WindowState = WindowState.Normal; Activate(); };
    }

    private async void ScanCleanup(object sender, RoutedEventArgs e)
    {
        await Run("Поиск временных файлов и кэша…", async token => {
            var result = await cleaner.ScanAsync(token);
            rubbish.Clear();
            foreach (var file in result.Files) rubbish.Add(new(file));
            CleanupSummary.Text = $"{rubbish.Count:N0} файлов · {FormatBytes(result.Files.Sum(file => file.Length))}";
            AddActivity("Очистка: найдено " + CleanupSummary.Text + $". Пропущено: {result.SkippedCount}." + (result.LimitReached ? " Достигнут лимит 50 000 файлов; после очистки повтори поиск." : ""));
        });
    }
    private async void DeleteCleanup(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        var selected = CleanupGrid.SelectedItems.Cast<CleanupRow>().ToArray();
        if (selected.Length == 0) { StatusText.Text = "Выдели файлы для удаления (Ctrl / Shift)."; return; }
        if (!Confirm($"Удалить выбранные временные файлы безвозвратно?\n\nФайлов: {selected.Length:N0}\nОбъём: {FormatBytes(selected.Sum(row => row.File.Length))}\n\nИзменённые, занятые и защищённые файлы будут пропущены.")) return;
        await Run("Удаление подтверждённых файлов…", async token => {
            var result = await cleaner.DeleteAsync(selected.Select(row => row.File), token);
            freed += result.FreedBytes;
            FreedState.Text = FormatBytes(freed);
            var report = $"Удалено: {result.DeletedCount:N0}. Освобождено: {FormatBytes(result.FreedBytes)}. Пропущено с ошибкой: {result.Errors.Count}.";
            AddActivity(report);
            ShowText("Результат очистки", report + (result.Errors.Count > 0 ? "\n\n" + string.Join("\n", result.Errors.Take(30)) : ""));
            rubbish.Clear();
            CleanupSummary.Text = "Обнови поиск перед следующей очисткой";
        });
    }

    private async void RefreshProcesses(object sender, RoutedEventArgs e) => await Run("Получаю список процессов…", LoadProcesses);
    private async Task LoadProcesses(CancellationToken token)
    {
        var entries = await processes.GetProcessesAsync(token);
        tasks.Clear();
        foreach (var entry in entries) tasks.Add(new(entry));
        AddActivity("Список процессов обновлён: " + tasks.Count);
    }
    private async void CloseProcess(object sender, RoutedEventArgs e) => await StopProcess(false);
    private async void KillProcess(object sender, RoutedEventArgs e) => await StopProcess(true);
    private async Task StopProcess(bool force)
    {
        if (busy) return;
        if (ProcessGrid.SelectedItem is not ProcessRow row) { StatusText.Text = "Выбери приложение в списке."; return; }
        if (!row.Entry.CanStop) { ShowText("Процесс защищён", row.Entry.ProtectionReason); return; }
        var message = force ? "Принудительно завершить процесс? Несохранённые данные могут быть потеряны." : "Отправить приложению запрос на закрытие? Сначала сохрани документы.";
        if (!Confirm(message + "\n\n" + row.Name + " · PID " + row.Id)) return;
        await Run(force ? "Завершение процесса…" : "Закрытие приложения…", async token => {
            var result = await processes.StopAsync(row.Entry, force, token);
            AddActivity(result.Message);
            ShowText(result.Success ? "Готово" : "Результат", result.Message);
            await LoadProcesses(token);
        });
    }

    private void RefreshVault(object sender, RoutedEventArgs e) => RefreshVaultData();
    private void RefreshVaultData()
    {
        try
        {
            var entries = quarantine.ListEntries();
            vault.Clear();
            foreach (var entry in entries) vault.Add(new(entry));
            VaultState.Text = vault.Count.ToString(CultureInfo.InvariantCulture);
        }
        catch (Exception ex) { VaultState.Text = "Ошибка"; AddActivity("Не удалось прочитать карантин: " + ex.Message); }
    }
    private async void RestoreSelected(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        if (VaultGrid.SelectedItem is not VaultRow row) { StatusText.Text = "Выбери файл в карантине."; return; }
        if (!Confirm("Восстановить потенциально опасный файл в исходную папку?\n\n" + row.OriginalPath + "\n\nФайл не будет запущен. Защита Windows может снова его обнаружить. Существующие файлы не перезаписываются.")) return;
        await Run("Восстановление файла…", async token => {
            await quarantine.RestoreAsync(row.Entry.Id, token);
            AddActivity("Файл восстановлен по подтверждению: " + row.OriginalPath);
            RefreshVaultData();
        });
    }

    private void AddActivity(string text)
    {
        activity.Insert(0, DateTime.Now.ToString("HH:mm") + "   " + text);
        if (activity.Count > 100) activity.RemoveAt(activity.Count - 1);
    }
    private bool Confirm(string text) => MessageBox.Show(this, text, "HERMES — подтверждение", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes;
    private void ShowText(string title, string text)
    {
        if (closing) return;
        var body = new TextBox { Text = text, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Background = System.Windows.Media.Brushes.Transparent, Foreground = (System.Windows.Media.Brush)FindResource("Ink"), BorderThickness = new Thickness(0), Padding = new Thickness(8) };
        var panel = new DockPanel { Margin = new Thickness(24) };
        var close = new Button { Content = "Понятно", HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0,15,0,0), MinWidth = 100 };
        DockPanel.SetDock(close, Dock.Bottom);
        panel.Children.Add(close); panel.Children.Add(body);
        var dialog = new Window { Owner = this, Title = "HERMES — " + title, Width = 720, Height = 430, MinHeight = 280, MinWidth = 500, WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = (System.Windows.Media.Brush)FindResource("Base"), Content = panel };
        close.Click += (_, _) => dialog.Close();
        dialog.ShowDialog();
    }
    public static string FormatBytes(long value)
    {
        string[] units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
        var number = (double)value; var unit = 0;
        while (number >= 1024 && unit < units.Length - 1) { number /= 1024; unit++; }
        return number.ToString(unit == 0 ? "N0" : "N1", CultureInfo.GetCultureInfo("ru-RU")) + " " + units[unit];
    }
    private static string GetDownloadsFolder()
    {
        if (OperatingSystem.IsWindows())
        {
            IntPtr pointer = IntPtr.Zero;
            try
            {
                var id = new Guid("374DE290-123F-4565-9164-39C4925E467B");
                if (SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out pointer) == 0 && Marshal.PtrToStringUni(pointer) is string path) return path;
            }
            finally { if (pointer != IntPtr.Zero) Marshal.FreeCoTaskMem(pointer); }
        }
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    }
    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath(ref Guid rfid, uint flags, IntPtr token, out IntPtr path);

    private sealed record ScanRow(ScanResult Result, string? Hash)
    {
        public string Path => Result.Path;
        public string Verdict => Result.Outcome switch { ScanOutcome.Clean => "Угрозы не обнаружены", ScanOutcome.ThreatDetected => "Обнаружена угроза", ScanOutcome.AttentionRequired => "Требует внимания", ScanOutcome.Cancelled => "Отменено", _ => "Не удалось проверить" };
    }
    private sealed record CleanupRow(CleanupFile File)
    {
        public string Path => File.Path;
        public string Category => File.Category;
        public string Size => FormatBytes(File.Length);
    }
    private sealed record ProcessRow(ProcessEntry Entry)
    {
        public int Id => Entry.Id;
        public string Name => Entry.Name;
        public string Memory => FormatBytes(Entry.WorkingSetBytes);
        public string Status => Entry.CanStop ? "Можно закрыть вручную" : Entry.ProtectionReason;
    }
    private sealed record VaultRow(QuarantineEntry Entry)
    {
        public string OriginalPath => Entry.OriginalPath;
        public string Date => Entry.QuarantinedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
    }
}
