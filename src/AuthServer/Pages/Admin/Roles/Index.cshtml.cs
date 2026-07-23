using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Hybrid;
using AuthServer.Data;

namespace AuthServer.Pages.Admin.Roles;

[Authorize(Roles = "admin")]
public class IndexModel : PageModel
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<IndexModel> _logger;
    private readonly HybridCache _hybridCache;

    public IndexModel(
        RoleManager<IdentityRole> roleManager, 
        UserManager<ApplicationUser> userManager, 
        ApplicationDbContext context,
        ILogger<IndexModel> logger,
        HybridCache hybridCache)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _context = context;
        _logger = logger;
        _hybridCache = hybridCache;
    }

    public List<RoleItem> Roles { get; set; } = new();
    public new int Page { get; set; } = 1;
    public int TotalPages { get; set; } = 1;
    public string? Search { get; set; }

    public async Task OnGetAsync(string? search, int page = 1)
    {
        Search = search;
        Page = page < 1 ? 1 : page;
        const int pageSize = 10;

        // 🟢 聯集計數查詢 (GroupJoin) 以消除 N+1 查詢風暴，將複雜度控制在單次 SQL 查詢
        var query = _context.Roles
            .GroupJoin(_context.UserRoles,
                role => role.Id,
                userRole => userRole.RoleId,
                (role, userRoles) => new RoleItem
                {
                    Name = role.Name ?? "",
                    UserCount = userRoles.Count()
                });

        // 關鍵字搜尋過濾 (不分大小寫模糊搜尋)
        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchTrim = search.Trim();
            query = query.Where(r => r.Name.Contains(searchTrim));
        }

        var totalCount = await query.CountAsync();
        TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
        if (Page > TotalPages && TotalPages > 0)
        {
            Page = TotalPages;
        }

        Roles = await query
            .OrderBy(r => r.Name)
            .Skip((Page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
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
        await _hybridCache.RemoveAsync("Dashboard_Stats");
        return RedirectToPage();
    }

    public class RoleItem
    {
        public string Name { get; set; } = "";
        public int UserCount { get; set; }
    }
}
