using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Caching.Hybrid;
using AuthServer.Data;

namespace AuthServer.Pages.Admin.Users;

[Authorize(Roles = "admin,UserManager,userBGMgr,userBUMgr")]
public class CreateModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<CreateModel> _logger;
    private readonly HybridCache _hybridCache;

    public CreateModel(
        UserManager<ApplicationUser> userManager, 
        RoleManager<IdentityRole> roleManager, 
        ILogger<CreateModel> logger,
        HybridCache hybridCache)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
        _hybridCache = hybridCache;
    }

    [BindProperty]
    public UserInput Input { get; set; } = new();

    [BindProperty]
    public List<string> SelectedRoles { get; set; } = new();

    public List<string> AvailableRoles { get; set; } = new();
    public string? ErrorMessage { get; set; }

    public bool IsBgReadOnly { get; set; }
    public bool IsBuReadOnly { get; set; }

    public async Task OnGetAsync()
    {
        AvailableRoles = _roleManager.Roles.OrderBy(r => r.Name).Select(r => r.Name!).ToList();

        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser != null)
        {
            var isBgAdmin = await _userManager.IsInRoleAsync(currentUser, "userBGMgr");
            var isBuAdmin = await _userManager.IsInRoleAsync(currentUser, "userBUMgr");

            if (isBgAdmin)
            {
                Input.BG = currentUser.BG;
                IsBgReadOnly = true;
            }
            else if (isBuAdmin)
            {
                Input.BG = currentUser.BG;
                Input.BU = currentUser.BU;
                IsBgReadOnly = true;
                IsBuReadOnly = true;
            }
        }
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            await LoadRolesAsync();
            return Page();
        }

        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser == null) return Forbid();

        var isGlobalAdmin = await _userManager.IsInRoleAsync(currentUser, "admin") || 
                            await _userManager.IsInRoleAsync(currentUser, "UserManager");
        var isBgAdmin = await _userManager.IsInRoleAsync(currentUser, "userBGMgr");
        var isBuAdmin = await _userManager.IsInRoleAsync(currentUser, "userBUMgr");

        // 🛡️ 新增用戶組織屬性防禦邏輯 (Create Security Gate)
        var finalBG = Input.BG?.Trim();
        var finalBU = Input.BU?.Trim();

        if (isBgAdmin)
        {
            // BG 管理員：強制限制建立的使用者只能屬於其所屬 BG
            finalBG = currentUser.BG;
        }
        else if (isBuAdmin)
        {
            // BU 管理員：強制限制建立的使用者必須同時屬於其所屬 BG 與 BU
            finalBG = currentUser.BG;
            finalBU = currentUser.BU;
        }

        var user = new ApplicationUser
        {
            UserName = Input.Email,  // 登入時使用 Email 作為帳號
            Email = Input.Email,
            EmailConfirmed = true,
            BG = finalBG,
            BU = finalBU,
            EMP_CD = Input.EMP_CD?.Trim()
        };

        var result = await _userManager.CreateAsync(user, Input.Password);
        if (!result.Succeeded)
        {
            ErrorMessage = string.Join("；", result.Errors.Select(e => e.Description));
            _logger.LogWarning("管理員 {AdminUser} 創建用戶失敗: {Error}", User.Identity?.Name, ErrorMessage);
            await LoadRolesAsync();
            return Page();
        }

        if (SelectedRoles.Count > 0)
        {
            await _userManager.AddToRolesAsync(user, SelectedRoles);
        }

        await _hybridCache.RemoveAsync("Dashboard_Stats");

        _logger.LogInformation("管理員 {AdminUser} 創建用戶 {UserEmail}", User.Identity?.Name, Input.Email);
        return RedirectToPage("Index");
    }

    private async Task LoadRolesAsync()
    {
        AvailableRoles = _roleManager.Roles.OrderBy(r => r.Name).Select(r => r.Name!).ToList();

        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser != null)
        {
            IsBgReadOnly = await _userManager.IsInRoleAsync(currentUser, "userBGMgr") || 
                           await _userManager.IsInRoleAsync(currentUser, "userBUMgr");
            IsBuReadOnly = await _userManager.IsInRoleAsync(currentUser, "userBUMgr");
        }
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
