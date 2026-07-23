using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Hybrid;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Pages.Admin.Roles;

[Authorize(Roles = "admin")]
public class CreateModel : PageModel
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<CreateModel> _logger;
    private readonly HybridCache _hybridCache;

    public CreateModel(RoleManager<IdentityRole> roleManager, ILogger<CreateModel> logger, HybridCache hybridCache)
    {
        _roleManager = roleManager;
        _logger = logger;
        _hybridCache = hybridCache;
    }

    [BindProperty]
    public RoleInput Input { get; set; } = new();

    public string? ErrorMessage { get; set; }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();

        if (await _roleManager.RoleExistsAsync(Input.Name))
        {
            ErrorMessage = $"角色 '{Input.Name}' 已存在。";
            _logger.LogWarning("管理員 {AdminUser} 創建角色失敗: 角色 {RoleName} 已存在", User.Identity?.Name, Input.Name);
            return Page();
        }

        var result = await _roleManager.CreateAsync(new IdentityRole(Input.Name));
        if (!result.Succeeded)
        {
            ErrorMessage = string.Join("；", result.Errors.Select(e => e.Description));
            _logger.LogWarning("管理員 {AdminUser} 創建角色 {RoleName} 失敗: {Error}", User.Identity?.Name, Input.Name, ErrorMessage);
            return Page();
        }

        // 🛡️ 創建角色成功主動清除統計快取
        await _hybridCache.RemoveAsync("Dashboard_Stats");

        _logger.LogInformation("管理員 {AdminUser} 創建角色 {RoleName}", User.Identity?.Name, Input.Name);
        return RedirectToPage("Index");
    }

    public class RoleInput
    {
        [Required(ErrorMessage = "角色名稱為必填")]
        public string Name { get; set; } = "";
    }
}
