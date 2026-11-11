using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Hermes.Desktop;
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        var smoke = e.Args.Contains("--smoke-test");
        DispatcherUnhandledException += (_, args) => {
            if (smoke) { Shutdown(1); return; }
            MessageBox.Show("Операция не выполнена. " + args.Exception.Message, "HERMES", MessageBoxButton.OK, MessageBoxImage.Warning);
            args.Handled = true;
        };
        if (smoke)
        {
            StartupUri = null;
            var position = Array.IndexOf(e.Args, "--smoke-test");
            var output = e.Args.Length > position + 1 ? e.Args[position + 1] : Path.Combine(Path.GetTempPath(), "hermes-smoke");
            var window = new MainWindow(true);
            MainWindow = window;
            window.Loaded += async (_, _) => {
                try
                {
                    Directory.CreateDirectory(output);
                    for (var page = 0; page < 5; page++)
                    {
                        window.Pages.SelectedIndex = page;
                        await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                        window.UpdateLayout();
                        var bitmap = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
                        bitmap.Render(window);
                        var encoder = new PngBitmapEncoder();
                        encoder.Frames.Add(BitmapFrame.Create(bitmap));
                        using var file = File.Create(Path.Combine(output, $"hermes-page-{page}.png"));
                        encoder.Save(file);
                    }
                    File.WriteAllText(Path.Combine(output, "result.txt"), "All five HERMES views initialized and rendered. No system operations performed.");
                    Shutdown(0);
                }
                catch (Exception ex)
                {
                    Directory.CreateDirectory(output);
                    File.WriteAllText(Path.Combine(output, "error.txt"), ex.ToString());
                    Shutdown(1);
                }
            };
            window.Show();
        }
        base.OnStartup(e);
    }
}
