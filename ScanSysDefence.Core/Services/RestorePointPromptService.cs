using ScanSysDefence.Core.Remediation;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Core.Services;

public class RestorePointPromptService : IRestorePointPromptService
{
    private readonly ILogger _logger;
    private bool _alwaysCreate = false;
    private bool _neverCreate = false;

    public RestorePointPromptService(ILogger logger)
    {
        _logger = logger;
    }

    public Task<RestorePointPromptResult> PromptUserAsync(RestorePointPromptContext context)
    {
        // This will be implemented by the UI layer
        // The service just provides the interface
        _logger.Information("Restore point prompt requested for: {Action}", context.ActionDescription);
        
        // Return default - UI will override
        return Task.FromResult(new RestorePointPromptResult
        {
            ShouldCreateRestorePoint = false,
            Description = context.RecommendedDescription,
            Action = RestorePointPromptAction.SkipAndContinue
        });
    }

    public void SetUserPreference(bool alwaysCreate, bool neverCreate)
    {
        _alwaysCreate = alwaysCreate;
        _neverCreate = neverCreate;
    }

    public (bool alwaysCreate, bool neverCreate) GetUserPreference()
    {
        return (_alwaysCreate, _neverCreate);
    }
}

// UI Implementation will be in ScanSysDefence.UI project
public interface IUIRestorePointPromptService
{
    Task<RestorePointPromptResult> ShowPromptAsync(RestorePointPromptContext context);
}