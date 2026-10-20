using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using ScanSysDefence.Core.Models;

namespace ScanSysDefence.UI.Converters
{
    public class RiskLevelToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is RiskLevel level)
            {
                return level switch
                {
                    RiskLevel.Critical => new SolidColorBrush(Color.FromRgb(0xEF, 0x53, 0x50)),
                    RiskLevel.High => new SolidColorBrush(Color.FromRgb(0xFF, 0x98, 0x00)),
                    RiskLevel.Medium => new SolidColorBrush(Color.FromRgb(0xFF, 0xEB, 0x3B)),
                    RiskLevel.Low => new SolidColorBrush(Color.FromRgb(0x42, 0xA5, 0xF5)),
                    _ => new SolidColorBrush(Color.FromRgb(0x66, 0xBB, 0x6A)),
                };
            }
            return new SolidColorBrush(Color.FromRgb(0x9E, 0x9E, 0x9E));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }

    public class RiskLevelToTextConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is RiskLevel level)
            {
                return level switch
                {
                    RiskLevel.Critical => "Критический",
                    RiskLevel.High => "Высокий",
                    RiskLevel.Medium => "Средний",
                    RiskLevel.Low => "Низкий",
                    _ => "Информационный",
                };
            }
            return "Неизвестно";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }

    public class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool flag = value is bool b && b;
            if (parameter is string s && s.Equals("Inverse", StringComparison.OrdinalIgnoreCase))
                flag = !flag;
            return flag ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            value is Visibility v && v == Visibility.Visible;
    }

    public class InverseBoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool flag = value is bool b && b;
            return flag ? Visibility.Collapsed : Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            value is Visibility v && v != Visibility.Visible;
    }

    public class StringNotEmptyToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool notEmpty = value is string s && !string.IsNullOrWhiteSpace(s);
            if (parameter is string p && p.Equals("Inverse", StringComparison.OrdinalIgnoreCase))
                notEmpty = !notEmpty;
            return notEmpty ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }

    public class LongToSizeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is long bytes)
            {
                string[] units = { "B", "KB", "MB", "GB", "TB" };
                double size = bytes;
                int unit = 0;
                while (size >= 1024 && unit < units.Length - 1)
                {
                    size /= 1024;
                    unit++;
                }
                return $"{size:0.##} {units[unit]}";
            }
            return "0 B";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }
}
