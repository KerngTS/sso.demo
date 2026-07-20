using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace AuthServer.Pages.Admin.Scopes;

[Authorize(Roles = "admin,ScopeManager")]
public class IndexModel : PageModel
{
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(IOpenIddictScopeManager scopeManager, ILogger<IndexModel> logger)
    {
        _scopeManager = scopeManager;
        _logger = logger;
    }

    public List<ScopeItem> Scopes { get; set; } = new();
    public string? ErrorMessage { get; set; }

    public async Task OnGetAsync()
    {
        Scopes = new List<ScopeItem>();
        await foreach (var scope in _scopeManager.ListAsync())
        {
            Scopes.Add(new ScopeItem
            {
                Name = (await _scopeManager.GetNameAsync(scope)) ?? "",
                DisplayName = await _scopeManager.GetDisplayNameAsync(scope),
                Description = await _scopeManager.GetDescriptionAsync(scope),
                Resources = string.Join(", ", (await _scopeManager.GetResourcesAsync(scope)))
            });
        }
    }

    public async Task<IActionResult> OnGetDeleteAsync(string name)
    {
        var scope = await _scopeManager.FindByNameAsync(name);
        if (scope != null)
        {
            _logger.LogWarning("管理員 {AdminUser} 刪除 Scope {ScopeName}", User.Identity?.Name, name);
            await _scopeManager.DeleteAsync(scope);
        }
        return RedirectToPage();
    }

    public class ScopeItem
    {
        public string Name { get; set; } = "";
        public string? DisplayName { get; set; }
        public string? Description { get; set; }
        public string? Resources { get; set; }
    }
}
