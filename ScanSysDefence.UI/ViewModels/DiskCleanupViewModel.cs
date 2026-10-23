using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.UI.ViewModels;

public class DiskCleanupViewModel : INotifyPropertyChanged
{
    private readonly IDiskCleanupService _cleanupService;
    private DriveInfo? _selectedDrive;
    private DiskCleanupScanResult? _scanResult;
    private bool _isScanning;
    private bool _isCleaning;
    private string _statusMessage = "Выберите диск для сканирования";
    private double _progressPercent;
    private bool _createRestorePoint = true;
    private readonly List<CleanupItem> _trackedItems = new();

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand ScanCommand { get; }
    public ICommand CleanCommand { get; }

    public ObservableCollection<DriveInfo> Drives { get; } = new();
    public ObservableCollection<CleanupCategorySummary> CategorySummaries { get; } = new();
    public ObservableCollection<CleanupItem> Items { get; } = new();
    public ObservableCollection<CleanupCategory> Categories { get; } = new();

    public DriveInfo? SelectedDrive
    {
        get => _selectedDrive;
        set { _selectedDrive = value; OnPropertyChanged(); UpdateCommandStates(); }
    }

    public DiskCleanupScanResult? ScanResult
    {
        get => _scanResult;
        set { _scanResult = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasResults)); UpdateCommandStates(); }
    }

    public bool IsScanning
    {
        get => _isScanning;
        set { _isScanning = value; OnPropertyChanged(); UpdateCommandStates(); }
    }

    public bool IsCleaning
    {
        get => _isCleaning;
        set { _isCleaning = value; OnPropertyChanged(); UpdateCommandStates(); }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    public double ProgressPercent
    {
        get => _progressPercent;
        set { _progressPercent = value; OnPropertyChanged(); }
    }

    public bool CanScan => SelectedDrive != null && !IsScanning && !IsCleaning;
    public bool HasResults => ScanResult != null && ScanResult.Items.Any();
    public long SelectedSize => ScanResult?.SelectedSize ?? 0;
    public int SelectedFiles => ScanResult?.SelectedFiles ?? 0;
    public string SelectedSizeFormatted => FormatSize(SelectedSize);

    public bool CreateRestorePoint
    {
        get => _createRestorePoint;
        set { _createRestorePoint = value; OnPropertyChanged(); }
    }

    public DiskCleanupViewModel(IDiskCleanupService cleanupService)
    {
        _cleanupService = cleanupService;
        ScanCommand = new RelayCommand(async () => await ScanAsync(), () => CanScan);
        CleanCommand = new RelayCommand(async () => await CleanAsync(CreateRestorePoint),
            () => HasResults && !IsScanning && !IsCleaning);
    }

    public async Task InitializeAsync()
    {
        try
        {
            var drives = await _cleanupService.GetDrivesAsync();
            Drives.Clear();
            foreach (var drive in drives) Drives.Add(drive);

            if (SelectedDrive == null && Drives.Count > 0)
            {
                SelectedDrive = Drives[0];
            }

            var cats = await _cleanupService.GetCategoriesAsync();
            Categories.Clear();
            foreach (var cat in cats)
            {
                cat.PropertyChanged += OnCategoryPropertyChanged;
                Categories.Add(cat);
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка загрузки дисков: {ex.Message}";
        }
    }

    public async Task ScanAsync()
    {
        if (SelectedDrive == null) return;

        foreach (var old in _trackedItems) old.PropertyChanged -= OnItemPropertyChanged;
        _trackedItems.Clear();

        IsScanning = true;
        StatusMessage = "Сканирование диска...";
        ProgressPercent = 0;

        try
        {
            var settings = new CleanupScanSettings();
            var progress = new Progress<CleanupScanProgress>(p =>
            {
                ProgressPercent = p.ProgressPercent;
                StatusMessage = p.StatusMessage;
            });

            ScanResult = await _cleanupService.ScanAsync(SelectedDrive.Letter, settings, progress);

            CategorySummaries.Clear();
            foreach (var summary in ScanResult.CategorySummaries) CategorySummaries.Add(summary);

            Items.Clear();
            foreach (var item in ScanResult.Items.Where(i => i.CanDelete))
            {
                item.PropertyChanged += OnItemPropertyChanged;
                _trackedItems.Add(item);
                Items.Add(item);
            }

            ApplyCategoryDefaults();
            RefreshSelectionSummary();

            StatusMessage = $"Найдено {ScanResult.TotalFiles} файлов ({FormatSize(ScanResult.TotalSize)}), выбрано {ScanResult.SelectedFiles} ({FormatSize(ScanResult.SelectedSize)})";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка сканирования: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    public async Task CleanAsync(bool createRestorePoint)
    {
        if (ScanResult == null) return;

        var itemsToClean = Items.Where(i => i.IsSelected && i.CanDelete).ToList();
        if (!itemsToClean.Any())
        {
            StatusMessage = "Нет выбранных файлов для удаления";
            return;
        }

        IsCleaning = true;
        StatusMessage = "Очистка...";
        ProgressPercent = 0;

        try
        {
            var progress = new Progress<CleanupProgress>(p =>
            {
                ProgressPercent = p.ProgressPercent;
                StatusMessage = p.StatusMessage;
            });

            var result = await _cleanupService.CleanAsync(itemsToClean, createRestorePoint, progress);
            StatusMessage = $"Очистка завершена: удалено {result.FilesDeleted} файлов, освобождено {FormatSize(result.BytesFreed)}";
            
            await ScanAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка очистки: {ex.Message}";
        }
        finally
        {
            IsCleaning = false;
        }
    }

    public void ToggleCategory(string categoryId, bool isSelected)
    {
        if (Items == null) return;
        foreach (var item in Items.Where(i => i.CategoryId == categoryId))
        {
            item.IsSelected = isSelected;
        }
        RefreshSelectionSummary();
    }

    public void ToggleAll(bool isSelected)
    {
        foreach (var item in Items)
        {
            if (item.CanDelete) item.IsSelected = isSelected;
        }
        RefreshSelectionSummary();
    }

    private void OnItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(CleanupItem.IsSelected))
        {
            RefreshSelectionSummary();
        }
    }

    private void OnCategoryPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(CleanupCategory.IsSelectedByDefault) && sender is CleanupCategory category)
        {
            ToggleCategory(category.Id, category.IsSelectedByDefault);
        }
    }

    private void ApplyCategoryDefaults()
    {
        foreach (var item in Items)
        {
            var category = Categories.FirstOrDefault(c => c.Id == item.CategoryId);
            if (category != null)
            {
                item.IsSelected = category.IsSelectedByDefault;
            }
        }
    }

    private void RefreshSelectionSummary()
    {
        OnPropertyChanged(nameof(SelectedSize));
        OnPropertyChanged(nameof(SelectedFiles));
        OnPropertyChanged(nameof(SelectedSizeFormatted));
    }

    private void UpdateCommandStates()
    {
        OnPropertyChanged(nameof(CanScan));
        (ScanCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (CleanCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    private string FormatSize(long bytes)
    {
        string[] suffixes = { "Б", "КБ", "МБ", "ГБ", "ТБ" };
        int i = 0;
        double size = bytes;
        while (size >= 1024 && i < suffixes.Length - 1)
        {
            size /= 1024;
            i++;
        }
        return $"{size:F1} {suffixes[i]}";
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}