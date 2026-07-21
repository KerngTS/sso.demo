using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using AuthServer.Data;

namespace AuthServer.Areas.Identity.Pages.Account;

[AllowAnonymous]
public class ChangePasswordDirectModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<ChangePasswordDirectModel> _logger;

    public ChangePasswordDirectModel(
        UserManager<ApplicationUser> userManager,
        ILogger<ChangePasswordDirectModel> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [TempData]
    public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "請輸入電子郵件")]
        [EmailAddress(ErrorMessage = "電子郵件格式不正確")]
        public string Email { get; set; } = "";

        [Required(ErrorMessage = "請輸入舊密碼")]
        [DataType(DataType.Password)]
        [Display(Name = "舊密碼")]
        public string OldPassword { get; set; } = "";

        [Required(ErrorMessage = "請輸入新密碼")]
        [StringLength(100, ErrorMessage = "{0} 長度至少必須為 {2} 個字元。", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "新密碼")]
        public string NewPassword { get; set; } = "";

        [DataType(DataType.Password)]
        [Display(Name = "確認新密碼")]
        [Compare("NewPassword", ErrorMessage = "新密碼與確認密碼不相符。")]
        public string ConfirmPassword { get; set; } = "";
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(Input.Email);

        // 🛡️ 安全防護：抗帳號枚舉 (Account Enumeration Mitigation)
        if (user == null)
        {
            _logger.LogWarning("自服務密碼修改嘗試失敗：用戶 {Email} 不存在於資料庫", Input.Email);
            ModelState.AddModelError(string.Empty, "帳號或舊密碼不正確。");
            return Page();
        }

        // 核對舊密碼
        var isOldPasswordCorrect = await _userManager.CheckPasswordAsync(user, Input.OldPassword);
        if (!isOldPasswordCorrect)
        {
            _logger.LogWarning("自服務密碼修改嘗試失敗：用戶 {Email} 的舊密碼不正確", Input.Email);
            ModelState.AddModelError(string.Empty, "帳號或舊密碼不正確。");
            return Page();
        }

        // 直接變更密碼 (免發信)
        var result = await _userManager.ChangePasswordAsync(user, Input.OldPassword, Input.NewPassword);
        if (!result.Succeeded)
        {
            _logger.LogWarning("自服務密碼修改失敗：用戶 {Email} 變更失敗，原因: {Errors}", 
                Input.Email, string.Join("；", result.Errors.Select(e => e.Description)));

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();
        }

        _logger.LogInformation("用戶 {Email} 透過免發信自服務成功變更了密碼", Input.Email);
        TempData["StatusMessage"] = "您的密碼已成功變更！請使用新密碼登入。";
        return RedirectToPage("./Login");
    }
}
