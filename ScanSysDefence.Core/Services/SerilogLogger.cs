using Serilog;

namespace ScanSysDefence.Core.Services;

public class SerilogLogger : ILogger
{
    private readonly Serilog.ILogger _logger;

    public SerilogLogger(Serilog.ILogger logger)
    {
        _logger = logger;
    }

    public void Information(string messageTemplate, params object[] propertyValues)
    {
        _logger.Information(messageTemplate, propertyValues);
    }

    public void Warning(string messageTemplate, params object[] propertyValues)
    {
        _logger.Warning(messageTemplate, propertyValues);
    }

    public void Error(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        _logger.Error(exception, messageTemplate, propertyValues);
    }

    public void Error(string messageTemplate, params object[] propertyValues)
    {
        _logger.Error(messageTemplate, propertyValues);
    }

    public void Debug(string messageTemplate, params object[] propertyValues)
    {
        _logger.Debug(messageTemplate, propertyValues);
    }

    public void Debug(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        _logger.Debug(exception, messageTemplate, propertyValues);
    }

    public void Verbose(string messageTemplate, params object[] propertyValues)
    {
        _logger.Verbose(messageTemplate, propertyValues);
    }
}

public class SerilogLogger<TCategoryName> : ILogger<TCategoryName>
{
    private readonly Serilog.ILogger _logger;

    public SerilogLogger(Serilog.ILogger logger)
    {
        _logger = logger.ForContext<TCategoryName>();
    }

    public void Information(string messageTemplate, params object[] propertyValues)
    {
        _logger.Information(messageTemplate, propertyValues);
    }

    public void Warning(string messageTemplate, params object[] propertyValues)
    {
        _logger.Warning(messageTemplate, propertyValues);
    }

    public void Error(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        _logger.Error(exception, messageTemplate, propertyValues);
    }

    public void Error(string messageTemplate, params object[] propertyValues)
    {
        _logger.Error(messageTemplate, propertyValues);
    }

    public void Debug(string messageTemplate, params object[] propertyValues)
    {
        _logger.Debug(messageTemplate, propertyValues);
    }

    public void Debug(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        _logger.Debug(exception, messageTemplate, propertyValues);
    }

    public void Verbose(string messageTemplate, params object[] propertyValues)
    {
        _logger.Verbose(messageTemplate, propertyValues);
    }
}