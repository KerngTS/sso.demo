using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Pages.Admin.Roles;

[Authorize(Roles = "admin")]
public class EditModel : PageModel
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<EditModel> _logger;

    public EditModel(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager, ILogger<EditModel> logger)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public RoleEditInput Input { get; set; } = new();

    public string? Message { get; set; }
    public bool IsError { get; set; }
    public int UserCount { get; set; }

    public async Task<IActionResult> OnGetAsync(string name)
    {
        var role = await _roleManager.FindByNameAsync(name);
        if (role == null) return NotFound();

        var usersInRole = await _userManager.GetUsersInRoleAsync(name);
        UserCount = usersInRole.Count;

        Input = new RoleEditInput
        {
            OriginalName = name,
            Name = role.Name ?? name
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();

        var role = await _roleManager.FindByNameAsync(Input.OriginalName);
        if (role == null) return NotFound();

        if (!string.Equals(Input.Name, Input.OriginalName, StringComparison.OrdinalIgnoreCase))
        {
            if (await _roleManager.RoleExistsAsync(Input.Name))
            {
                Message = $"角色 '{Input.Name}' 已存在。";
                IsError = true;
                return Page();
            }

            role.Name = Input.Name;
            role.NormalizedName = Input.Name.Normalize().ToUpperInvariant();
            var result = await _roleManager.UpdateAsync(role);

            if (!result.Succeeded)
            {
                Message = string.Join("；", result.Errors.Select(e => e.Description));
                IsError = true;
                return Page();
            }
        }

        _logger.LogInformation("管理員 {AdminUser} 更新角色 {OldName} → {NewName}", User.Identity?.Name, Input.OriginalName, Input.Name);
        TempData["RoleMessage"] = "更新成功。";
        return RedirectToPage("Index");
    }

    public class RoleEditInput
    {
        public string OriginalName { get; set; } = "";

        [Required(ErrorMessage = "角色名稱為必填")]
        public string Name { get; set; } = "";
    }
}
