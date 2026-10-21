using System.Windows;
using ScanSysDefence.UI.ViewModels;

namespace ScanSysDefence.UI
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel _viewModel;

        public MainWindow(MainViewModel viewModel)
        {
            InitializeComponent();
            _viewModel = viewModel;
            DataContext = viewModel;

            Loaded += OnWindowLoaded;
        }

        private async void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            // Подгружаем список дисков и категории очистки
            await _viewModel.DiskCleanup.InitializeAsync();

            // Диски для антивирусной проверки и содержимое карантина
            await _viewModel.VirusScan.InitializeAsync();
            await _viewModel.Quarantine.InitializeAsync();
        }

        private void ThreatTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (e.NewValue is ThreatNode node && node.SourceItem != null)
            {
                _viewModel.Malware.SelectedItem = node.SourceItem;
            }
        }
    }
}
