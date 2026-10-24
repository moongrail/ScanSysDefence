using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Tests;

public class FakeLogger : ILogger
{
    public List<string> Messages { get; } = new();

    private static string Format(string prefix, string template, object[] args)
        => args is { Length: > 0 }
            ? $"{prefix}{template} [{string.Join("; ", args)}]"
            : prefix + template;

    public void Information(string messageTemplate, params object[] propertyValues) => Messages.Add(Format("I: ", messageTemplate, propertyValues));
    public void Warning(string messageTemplate, params object[] propertyValues) => Messages.Add(Format("W: ", messageTemplate, propertyValues));
    public void Error(Exception exception, string messageTemplate, params object[] propertyValues) => Messages.Add(Format("E: ", messageTemplate, propertyValues) + " (ex: " + exception.Message + ")");
    public void Error(string messageTemplate, params object[] propertyValues) => Messages.Add(Format("E: ", messageTemplate, propertyValues));
    public void Debug(string messageTemplate, params object[] propertyValues) => Messages.Add(Format("D: ", messageTemplate, propertyValues));
    public void Debug(Exception exception, string messageTemplate, params object[] propertyValues) => Messages.Add(Format("D: ", messageTemplate, propertyValues) + " (ex: " + exception.Message + ")");
    public void Verbose(string messageTemplate, params object[] propertyValues) => Messages.Add(Format("V: ", messageTemplate, propertyValues));
}

/// <summary>
/// Фейковый сервис подписей: по умолчанию файл не подписан,
/// можно задать результат для конкретного пути.
/// </summary>
public class FakeSignatureService : IDigitalSignatureService
{
    public Dictionary<string, DigitalSignatureInfo> Results { get; } = new(StringComparer.OrdinalIgnoreCase);

    public DigitalSignatureInfo DefaultResult { get; set; } = new();

    public Task<DigitalSignatureInfo> VerifySignatureAsync(string filePath) => VerifySignatureAsync(filePath, CancellationToken.None);

    public Task<DigitalSignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken)
    {
        var result = Results.TryGetValue(filePath, out var custom) ? custom : DefaultResult;
        return Task.FromResult(result);
    }
}

/// <summary>
/// Заглушка ISafetyService: методы не должны вызываться в юнит-тестах.
/// </summary>
public class SafetyServiceStub : ISafetyService
{
    public Task<SafetyCheckResult> ValidateActionAsync(ScanSysDefence.Core.Remediation.RemediationAction action, ScanItemBase target)
        => throw new NotSupportedException();
    public Task<SafetyCheckResult> ValidateBatchAsync(List<ScanSysDefence.Core.Remediation.RemediationAction> actions, IEnumerable<ScanItemBase> targets)
        => throw new NotSupportedException();
    public Task<SystemHealthSnapshot> CaptureSystemHealthAsync() => throw new NotSupportedException();
    public Task<SystemHealthComparison> CompareSystemHealthAsync(SystemHealthSnapshot before) => throw new NotSupportedException();
    public Task<bool> IsSystemCriticalAsync(ScanItemBase item) => throw new NotSupportedException();
    public Task<List<string>> GetDependenciesAsync(ScanItemBase item) => throw new NotSupportedException();
    public Task<RollbackToken> CreateRollbackPointAsync(string description) => throw new NotSupportedException();
    public Task<RollbackResult> RollbackAsync(RollbackToken token) => throw new NotSupportedException();
    public Task<List<RollbackToken>> GetAvailableRollbacksAsync() => throw new NotSupportedException();
    public Task<bool> IsActionReversibleAsync(ScanSysDefence.Core.Remediation.RemediationAction action) => throw new NotSupportedException();
    public Task<SimulationResult> SimulateActionAsync(ScanSysDefence.Core.Remediation.RemediationAction action, ScanItemBase target)
        => throw new NotSupportedException();
}

/// <summary>Заглушка сервиса точек восстановления (в юнит-тестах не используется).</summary>
public class RestorePointServiceStub : IRestorePointService
{
    public Task<bool> CreateRestorePointAsync(string description) => Task.FromResult(false);
    public Task<bool> IsSystemRestoreEnabledAsync() => Task.FromResult(false);
    public Task<List<RestorePointInfo>> GetRestorePointsAsync() => Task.FromResult(new List<RestorePointInfo>());
    public Task<bool> DeleteRestorePointAsync(string sequenceNumber) => Task.FromResult(false);
}

/// <summary>Заглушка диалога точки восстановления: всегда «пропустить».</summary>
public class RestorePointPromptServiceStub : ScanSysDefence.Core.Remediation.IRestorePointPromptService
{
    public Task<ScanSysDefence.Core.Remediation.RestorePointPromptResult> PromptUserAsync(
        ScanSysDefence.Core.Remediation.RestorePointPromptContext context)
        => Task.FromResult(new ScanSysDefence.Core.Remediation.RestorePointPromptResult
        {
            Action = ScanSysDefence.Core.Remediation.RestorePointPromptAction.SkipAndContinue,
            ShouldCreateRestorePoint = false
        });

    public void SetUserPreference(bool alwaysCreate, bool neverCreate) { }
    public (bool alwaysCreate, bool neverCreate) GetUserPreference() => (false, true);
}
