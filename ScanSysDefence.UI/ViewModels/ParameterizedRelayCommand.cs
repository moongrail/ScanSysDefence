using System.Windows.Input;

namespace ScanSysDefence.UI.ViewModels;

/// <summary>Команда с параметром (например, фаза сканирования в CommandParameter).</summary>
public class ParameterizedRelayCommand<T> : ICommand
{
    private readonly Func<T?, Task> _asyncExecute;
    private readonly Func<T?, bool>? _canExecute;

    public event EventHandler? CanExecuteChanged;

    public ParameterizedRelayCommand(Func<T?, Task> asyncExecute, Func<T?, bool>? canExecute = null)
    {
        _asyncExecute = asyncExecute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(Convert(parameter)) ?? true;

    public async void Execute(object? parameter) => await _asyncExecute(Convert(parameter));

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);

    private static T? Convert(object? parameter)
    {
        if (parameter is T typed) return typed;
        if (parameter == null) return default;
        try
        {
            if (typeof(T) == typeof(string)) return (T?)(object?)parameter.ToString();
            return (T?)System.Convert.ChangeType(parameter, typeof(T));
        }
        catch
        {
            return default;
        }
    }
}
