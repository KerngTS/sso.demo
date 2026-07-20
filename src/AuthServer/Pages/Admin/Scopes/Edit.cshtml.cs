using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Pages.Admin.Scopes;

[Authorize(Roles = "admin,ScopeManager")]
public class EditModel : PageModel
{
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<EditModel> _logger;

    public EditModel(IOpenIddictScopeManager scopeManager, ILogger<EditModel> logger)
    {
        _scopeManager = scopeManager;
        _logger = logger;
    }

    [BindProperty]
    public ScopeEditInput Input { get; set; } = new();

    public string? ErrorMessage { get; set; }

    public async Task<IActionResult> OnGetAsync(string name)
    {
        var scope = await _scopeManager.FindByNameAsync(name);
        if (scope == null) return NotFound();

        Input = new ScopeEditInput
        {
            OriginalName = name,
            Name = await _scopeManager.GetNameAsync(scope) ?? name,
            DisplayName = await _scopeManager.GetDisplayNameAsync(scope),
            Description = await _scopeManager.GetDescriptionAsync(scope),
            Resources = string.Join(", ", (await _scopeManager.GetResourcesAsync(scope)))
        };
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();

        try
        {
            var scope = await _scopeManager.FindByNameAsync(Input.OriginalName);
            if (scope == null) return NotFound();

            // 使用 PopulateAsync + UpdateAsync 更新
            // 簡化：刪除舊的並建立新的（帶相同 Id）
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

            await _scopeManager.UpdateAsync(scope, descriptor);
            _logger.LogInformation("管理員 {AdminUser} 更新 Scope {ScopeName}", User.Identity?.Name, Input.OriginalName);
            return RedirectToPage("Index");
        }
        catch (Exception ex)
        {
            ErrorMessage = $"更新失敗：{ex.Message}";
            _logger.LogWarning("管理員 {AdminUser} 更新 Scope {ScopeName} 失敗: {Error}", User.Identity?.Name, Input.OriginalName, ex.Message);
            return Page();
        }
    }

    public class ScopeEditInput
    {
        public string OriginalName { get; set; } = "";

        [Required(ErrorMessage = "Scope 名稱為必填")]
        public string Name { get; set; } = "";

        public string? DisplayName { get; set; }
        public string? Description { get; set; }
        public string? Resources { get; set; }
    }
}
