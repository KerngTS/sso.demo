using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Hybrid;
using AuthServer.Data;

namespace AuthServer.Pages.Admin.Users;

[Authorize(Roles = "admin,UserManager,userBGMgr,userBUMgr")]
public class EditModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<EditModel> _logger;
    private readonly HybridCache _hybridCache;

    public EditModel(
        UserManager<ApplicationUser> userManager, 
        RoleManager<IdentityRole> roleManager, 
        ILogger<EditModel> logger,
        HybridCache hybridCache)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
        _hybridCache = hybridCache;
    }

    [BindProperty]
    public UserEditInput Input { get; set; } = new();

    [BindProperty]
    public List<string> SelectedRoles { get; set; } = new();

    public List<string> AvailableRoles { get; set; } = new();
    public string? Message { get; set; }
    public bool IsError { get; set; }
    public string CurrentUserId => User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "";

    public bool IsBgReadOnly { get; set; }
    public bool IsBuReadOnly { get; set; }

    public async Task<IActionResult> OnGetAsync(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        // 🛡️ 數據防越權檢查 (Access Security Gate)
        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser == null) return Forbid();

        var isGlobalAdmin = await _userManager.IsInRoleAsync(currentUser, "admin") || 
                            await _userManager.IsInRoleAsync(currentUser, "UserManager");
        var isBgAdmin = await _userManager.IsInRoleAsync(currentUser, "userBGMgr");
        var isBuAdmin = await _userManager.IsInRoleAsync(currentUser, "userBUMgr");

        if (isBgAdmin && user.BG != currentUser.BG)
        {
            return Forbid();
        }
        if (isBuAdmin && (user.BG != currentUser.BG || user.BU != currentUser.BU))
        {
            return Forbid();
        }

        IsBgReadOnly = isBgAdmin || isBuAdmin;
        IsBuReadOnly = isBuAdmin;

        // 從 TempData 讀取上一個請求的訊息
        Message = TempData["Message"] as string;
        IsError = TempData["IsError"] as string == "true";

        AvailableRoles = _roleManager.Roles.OrderBy(r => r.Name).Select(r => r.Name!).ToList();

        Input = new UserEditInput
        {
            Id = user.Id,
            UserName = user.UserName ?? "",
            Email = user.Email,
            Roles = (await _userManager.GetRolesAsync(user)).ToList(),
            IsDisabled = user.LockoutEnabled && user.LockoutEnd > DateTimeOffset.UtcNow,
            BG = user.BG,
            BU = user.BU,
            EMP_CD = user.EMP_CD
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var user = await _userManager.FindByIdAsync(Input.Id);
        if (user == null) return NotFound();

        // 🛡️ 數據防越權檢查 (Write Security Gate)
        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser == null) return Forbid();

        var isGlobalAdmin = await _userManager.IsInRoleAsync(currentUser, "admin") || 
                            await _userManager.IsInRoleAsync(currentUser, "UserManager");
        var isBgAdmin = await _userManager.IsInRoleAsync(currentUser, "userBGMgr");
        var isBuAdmin = await _userManager.IsInRoleAsync(currentUser, "userBUMgr");

        if (isBgAdmin && user.BG != currentUser.BG)
        {
            return Forbid();
        }
        if (isBuAdmin && (user.BG != currentUser.BG || user.BU != currentUser.BU))
        {
            return Forbid();
        }

        // 禁止禁用自己的帳號
        if (Input.IsDisabled && Input.Id == CurrentUserId)
        {
            TempData["Message"] = "不可禁用自己的帳號。";
            TempData["IsError"] = "true";
            return RedirectToPage(new { id = Input.Id });
        }

        // 更新 Email（同步更新 UserName，因為登入用 Email）"
        if (user.Email != Input.Email)
        {
            user.Email = Input.Email;
            user.UserName = Input.Email;
            user.NormalizedEmail = _userManager.NormalizeEmail(Input.Email);
            user.NormalizedUserName = _userManager.NormalizeName(Input.Email);
        }

        // 更新組織屬性 (根據操作者權限限制其可以編輯的屬性)
        if (isGlobalAdmin)
        {
            user.BG = Input.BG?.Trim();
            user.BU = Input.BU?.Trim();
        }
        else if (isBgAdmin)
        {
            // BG 管理員不可修改使用者的 BG，只能變更 BU 
            user.BU = Input.BU?.Trim();
        }
        // BU 管理員 (isBuAdmin) 不可修改任何組織屬性 (BG 與 BU 皆被鎖定)

        user.EMP_CD = Input.EMP_CD?.Trim();

        await _userManager.UpdateAsync(user);

        // 更新禁用狀態
        if (Input.IsDisabled)
        {
            await _userManager.SetLockoutEnabledAsync(user, true);
            await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
        }
        else
        {
            await _userManager.SetLockoutEndDateAsync(user, null);
        }

        // 同步角色
        var currentRoles = await _userManager.GetRolesAsync(user);
        var toAdd = SelectedRoles.Except(currentRoles).ToList();
        var toRemove = currentRoles.Except(SelectedRoles).ToList();

        if (toAdd.Count > 0)
            await _userManager.AddToRolesAsync(user, toAdd);
        if (toRemove.Count > 0)
            await _userManager.RemoveFromRolesAsync(user, toRemove);

        // 🛡️ 異動成功後主動清除對應快取 (Cache Eviction)
        await _hybridCache.RemoveAsync("Dashboard_Stats");
        await _hybridCache.RemoveAsync($"User_Claims_{Input.Id}");

        _logger.LogInformation("管理員 {AdminUser} 更新用戶 {TargetUserId} (Email={Email}, IsDisabled={IsDisabled}, BG={BG}, BU={BU}, EMP_CD={EMP_CD})",
            User.Identity?.Name, Input.Id, Input.Email, Input.IsDisabled, user.BG, user.BU, user.EMP_CD);

        TempData["Message"] = "更新成功。";
        TempData["IsError"] = "false";
        return RedirectToPage(new { id = Input.Id });
    }

    public async Task<IActionResult> OnPostResetPasswordAsync(string id, string newPassword)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        // 🛡️ 數據防越權檢查 (Password Reset Security Gate)
        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser == null) return Forbid();

        var isGlobalAdmin = await _userManager.IsInRoleAsync(currentUser, "admin") || 
                            await _userManager.IsInRoleAsync(currentUser, "UserManager");
        var isBgAdmin = await _userManager.IsInRoleAsync(currentUser, "userBGMgr");
        var isBuAdmin = await _userManager.IsInRoleAsync(currentUser, "userBUMgr");

        if (isBgAdmin && user.BG != currentUser.BG)
        {
            return Forbid();
        }
        if (isBuAdmin && (user.BG != currentUser.BG || user.BU != currentUser.BU))
        {
            return Forbid();
        }

        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 6)
        {
            TempData["Message"] = "密碼至少 6 個字元。";
            TempData["IsError"] = "true";
            return RedirectToPage(new { id });
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);

        if (result.Succeeded)
        {
            // 🛡️ 密碼重設成功後清除用戶資訊快取
            await _hybridCache.RemoveAsync($"User_Claims_{id}");

            _logger.LogWarning("管理員 {AdminUser} 重設用戶 {TargetUserId} 密碼", User.Identity?.Name, id);
            TempData["Message"] = "密碼重設成功。";
            TempData["IsError"] = "false";
        }
        else
        {
            _logger.LogWarning("管理員 {AdminUser} 重設用戶 {TargetUserId} 密碼失敗: {Error}", User.Identity?.Name, id,
                string.Join("；", result.Errors.Select(e => e.Description)));
            TempData["Message"] = string.Join("；", result.Errors.Select(e => e.Description));
            TempData["IsError"] = "true";
        }

        return RedirectToPage(new { id });
    }

    private async Task LoadFormDataAsync(ApplicationUser user)
    {
        AvailableRoles = _roleManager.Roles.OrderBy(r => r.Name).Select(r => r.Name!).ToList();

        Input = new UserEditInput
        {
            Id = user.Id,
            UserName = user.UserName ?? "",
            Email = user.Email,
            Roles = (await _userManager.GetRolesAsync(user)).ToList(),
            IsDisabled = user.LockoutEnabled && user.LockoutEnd > DateTimeOffset.UtcNow,
            BG = user.BG,
            BU = user.BU,
            EMP_CD = user.EMP_CD
        };
    }

    public class UserEditInput
    {
        public string Id { get; set; } = "";
        public string UserName { get; set; } = "";

        [Required(ErrorMessage = "Email 為必填")]
        [EmailAddress(ErrorMessage = "Email 格式無效")]
        public string? Email { get; set; }

        public List<string> Roles { get; set; } = new();
        public bool IsDisabled { get; set; }

        [Display(Name = "事業群 (BG)")]
        [MaxLength(50)]
        public string? BG { get; set; }

        [Display(Name = "事業處 (BU)")]
        [MaxLength(50)]
        public string? BU { get; set; }

        [Display(Name = "員工工號 (EMP_CD)")]
        [MaxLength(50)]
        public string? EMP_CD { get; set; }
    }
}
