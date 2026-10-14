namespace ScanSysDefence.Core.Services;

public interface ILogger
{
    void Information(string messageTemplate, params object[] propertyValues);
    void Warning(string messageTemplate, params object[] propertyValues);
    void Error(Exception exception, string messageTemplate, params object[] propertyValues);
    void Error(string messageTemplate, params object[] propertyValues);
    void Debug(string messageTemplate, params object[] propertyValues);
    void Debug(Exception exception, string messageTemplate, params object[] propertyValues);
    void Verbose(string messageTemplate, params object[] propertyValues);
}

public interface ILogger<out TCategoryName> : ILogger { }