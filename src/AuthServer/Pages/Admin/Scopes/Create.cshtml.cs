using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Hybrid;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Pages.Admin.Scopes;

[Authorize(Roles = "admin,ScopeManager")]
public class CreateModel : PageModel
{
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<CreateModel> _logger;
    private readonly HybridCache _hybridCache;

    public CreateModel(IOpenIddictScopeManager scopeManager, ILogger<CreateModel> logger, HybridCache hybridCache)
    {
        _scopeManager = scopeManager;
        _logger = logger;
        _hybridCache = hybridCache;
    }

    [BindProperty]
    public ScopeInput Input { get; set; } = new();

    public string? ErrorMessage { get; set; }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();

        try
        {
            var existing = await _scopeManager.FindByNameAsync(Input.Name);
            if (existing != null)
            {
                ErrorMessage = $"Scope '{Input.Name}' 已存在。";
                return Page();
            }

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = Input.Name,
                DisplayName = Input.DisplayName,
                Description = Input.Description
            };

            var resources = Input.Resources?
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (resources != null)
            {
                foreach (var r in resources)
                    descriptor.Resources.Add(r);
            }

            await _scopeManager.CreateAsync(descriptor);

            // 🛡️ 建立成功主動清除統計快取
            await _hybridCache.RemoveAsync("Dashboard_Stats");

            _logger.LogInformation("管理員 {AdminUser} 創建 Scope {ScopeName}", User.Identity?.Name, Input.Name);
            return RedirectToPage("Index");
        }
        catch (Exception ex)
        {
            ErrorMessage = $"建立失敗：{ex.Message}";
            _logger.LogWarning("管理員 {AdminUser} 創建 Scope 失敗: {Error}", User.Identity?.Name, ex.Message);
            return Page();
        }
    }

    public class ScopeInput
    {
        [Required(ErrorMessage = "Scope 名稱為必填")]
        public string Name { get; set; } = "";

        public string? DisplayName { get; set; }
        public string? Description { get; set; }
        public string? Resources { get; set; }
    }
}
