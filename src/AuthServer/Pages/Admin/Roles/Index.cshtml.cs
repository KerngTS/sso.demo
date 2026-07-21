using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AuthServer.Data;

namespace AuthServer.Pages.Admin.Roles;

[Authorize(Roles = "admin")]
public class IndexModel : PageModel
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager, ILogger<IndexModel> logger)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _logger = logger;
    }

    public List<RoleItem> Roles { get; set; } = new();

    public async Task OnGetAsync()
    {
        Roles = new List<RoleItem>();
        var roles = _roleManager.Roles.OrderBy(r => r.Name).ToList();

        foreach (var role in roles)
        {
            var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
            Roles.Add(new RoleItem
            {
                Name = role.Name ?? "",
                UserCount = usersInRole.Count
            });
        }
    }

    public async Task<IActionResult> OnGetDeleteAsync(string name)
    {
        var role = await _roleManager.FindByNameAsync(name);
        if (role == null) return RedirectToPage();

        // 檢查是否仍有使用者持有此角色
        var usersInRole = await _userManager.GetUsersInRoleAsync(name);
        if (usersInRole.Count > 0)
        {
            return RedirectToPage();
        }

        _logger.LogWarning("管理員 {AdminUser} 刪除角色 {RoleName}", User.Identity?.Name, name);
        await _roleManager.DeleteAsync(role);
        return RedirectToPage();
    }

    public class RoleItem
    {
        public string Name { get; set; } = "";
        public int UserCount { get; set; }
    }
}
