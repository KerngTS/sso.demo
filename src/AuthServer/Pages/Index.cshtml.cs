using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Hybrid;
using OpenIddict.Abstractions;
using AuthServer.Data;

namespace AuthServer.Pages;

[Authorize(Roles = "admin,UserManager,ClientManager,ScopeManager,userBGMgr,userBUMgr")]
public class IndexModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IOpenIddictApplicationManager _appManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly HybridCache _hybridCache;

    public int UserCount { get; set; }
    public int RoleCount { get; set; }
    public int ClientCount { get; set; }
    public int ScopeCount { get; set; }

    public IndexModel(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOpenIddictApplicationManager appManager,
        IOpenIddictScopeManager scopeManager,
        HybridCache hybridCache)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _appManager = appManager;
        _scopeManager = scopeManager;
        _hybridCache = hybridCache;
    }

    public async Task OnGetAsync()
    {
        // 🛡️ Stampede Protection: 內建鎖定與排隊防護，保障高併發下資料庫安全
        var stats = await _hybridCache.GetOrCreateAsync("Dashboard_Stats", async token =>
        {
            var userCount = await _userManager.Users.CountAsync(token);
            var roleCount = await _roleManager.Roles.CountAsync(token);

            // 🛡️ O(1) 原生 SQL 計數：直接對資料庫執行 COUNT 查詢，避免 O(N) 遍歷與記憶體過載
            var clientCount = (int)await _appManager.CountAsync(token);
            var scopeCount = (int)await _scopeManager.CountAsync(token);

            return new DashboardStats
            {
                UserCount = userCount,
                RoleCount = roleCount,
                ClientCount = clientCount,
                ScopeCount = scopeCount
            };
        });

        UserCount = stats.UserCount;
        RoleCount = stats.RoleCount;
        ClientCount = stats.ClientCount;
        ScopeCount = stats.ScopeCount;
    }

    public class DashboardStats
    {
        public int UserCount { get; set; }
        public int RoleCount { get; set; }
        public int ClientCount { get; set; }
        public int ScopeCount { get; set; }
    }
}
