using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using AuthServer.Data;

namespace AuthServer.Pages.Admin.Users;

[Authorize(Roles = "admin,UserManager")]
public class CreateModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<CreateModel> _logger;

    public CreateModel(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, ILogger<CreateModel> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
    }

    [BindProperty]
    public UserInput Input { get; set; } = new();

    [BindProperty]
    public List<string> SelectedRoles { get; set; } = new();

    public List<string> AvailableRoles { get; set; } = new();
    public string? ErrorMessage { get; set; }

    public void OnGet()
    {
        AvailableRoles = _roleManager.Roles.OrderBy(r => r.Name).Select(r => r.Name!).ToList();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            LoadRoles();
            return Page();
        }

        var user = new ApplicationUser
        {
            UserName = Input.Email,  // 登入時使用 Email 作為帳號
            Email = Input.Email,
            EmailConfirmed = true,
            BG = Input.BG?.Trim(),
            BU = Input.BU?.Trim(),
            EMP_CD = Input.EMP_CD?.Trim()
        };

        var result = await _userManager.CreateAsync(user, Input.Password);
        if (!result.Succeeded)
        {
            ErrorMessage = string.Join("；", result.Errors.Select(e => e.Description));
            _logger.LogWarning("管理員 {AdminUser} 創建用戶失敗: {Error}", User.Identity?.Name, ErrorMessage);
            LoadRoles();
            return Page();
        }

        if (SelectedRoles.Count > 0)
        {
            await _userManager.AddToRolesAsync(user, SelectedRoles);
        }

        _logger.LogInformation("管理員 {AdminUser} 創建用戶 {UserEmail}", User.Identity?.Name, Input.Email);
        return RedirectToPage("Index");
    }

    private void LoadRoles()
    {
        AvailableRoles = _roleManager.Roles.OrderBy(r => r.Name).Select(r => r.Name!).ToList();
    }

    public class UserInput
    {
        [Required(ErrorMessage = "Email 為必填")]
        [EmailAddress(ErrorMessage = "Email 格式無效")]
        public string Email { get; set; } = "";

        [Required(ErrorMessage = "密碼為必填")]
        [MinLength(6, ErrorMessage = "密碼至少 6 個字元")]
        public string Password { get; set; } = "";

        [Display(Name = "事業群 (BG)")]
        [MaxLength(50, ErrorMessage = "事業群字數不可超過 50")]
        public string? BG { get; set; }

        [Display(Name = "事業處 (BU)")]
        [MaxLength(50, ErrorMessage = "事業處字數不可超過 50")]
        public string? BU { get; set; }

        [Display(Name = "員工工號 (EMP_CD)")]
        [MaxLength(50, ErrorMessage = "員工工號字數不可超過 50")]
        public string? EMP_CD { get; set; }
    }
}
