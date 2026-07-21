using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using AuthServer.Data;

namespace AuthServer.Pages.Admin.Users;

[Authorize(Roles = "admin,UserManager,userBGMgr,userBUMgr")]
public class IndexModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;

    public IndexModel(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public List<UserItem> Users { get; set; } = new();
    public int Page { get; set; } = 1;
    public int TotalPages { get; set; } = 1;
    public string? Search { get; set; }
    public string? BgFilter { get; set; }
    public string? BuFilter { get; set; }

    // 用於管理員篩選的下拉選單選項
    public List<string> AvailableBGs { get; set; } = new();
    public List<string> AvailableBUs { get; set; } = new();

    public bool CanFilterAll { get; set; }

    public async Task OnGetAsync(string? search, string? bgFilter, string? buFilter, int page = 1)
    {
        Search = search;
        BgFilter = bgFilter;
        BuFilter = buFilter;
        Page = page < 1 ? 1 : page;
        const int pageSize = 10;

        var currentUser = await _userManager.GetUserAsync(User);
        if (currentUser == null) return;

        var isGlobalAdmin = await _userManager.IsInRoleAsync(currentUser, "admin") || 
                            await _userManager.IsInRoleAsync(currentUser, "UserManager");
        var isBgAdmin = await _userManager.IsInRoleAsync(currentUser, "userBGMgr");
        var isBuAdmin = await _userManager.IsInRoleAsync(currentUser, "userBUMgr");

        CanFilterAll = isGlobalAdmin;

        var query = _userManager.Users.AsQueryable();

        // 🟢 組織數據權限隔離 (Data Isolation Gate)
        if (isGlobalAdmin)
        {
            // 全域管理員：可以使用畫面上的 BG / BU 下拉進行過濾
            if (!string.IsNullOrEmpty(bgFilter))
            {
                query = query.Where(u => u.BG == bgFilter);
            }
            if (!string.IsNullOrEmpty(buFilter))
            {
                query = query.Where(u => u.BU == buFilter);
            }
        }
        else if (isBgAdmin)
        {
            // BG 管理員：強制只能看見並管理相同 BG 下的所有用戶 (跨多個 BU)
            var userBg = currentUser.BG ?? "UNKNOWN_BG";
            query = query.Where(u => u.BG == userBg);

            // 僅允許篩選其所屬 BG 內部的 BU
            if (!string.IsNullOrEmpty(buFilter))
            {
                query = query.Where(u => u.BU == buFilter);
            }
        }
        else if (isBuAdmin)
        {
            // BU 管理員：強制只能看見並管理相同 BG 且相同 BU 下的用戶 (雙重比對隔離，防跨 BG 越權)
            var userBg = currentUser.BG ?? "UNKNOWN_BG";
            var userBu = currentUser.BU ?? "UNKNOWN_BU";
            query = query.Where(u => u.BG == userBg && u.BU == userBu);
        }
        else
        {
            // 其他身分：無權限查看
            query = query.Where(u => false);
        }

        // 關鍵字搜尋過濾
        if (!string.IsNullOrWhiteSpace(search))
        {
            search = search.Trim();
            query = query.Where(u => (u.UserName != null && u.UserName.Contains(search))
                                  || (u.Email != null && u.Email.Contains(search))
                                  || (u.EMP_CD != null && u.EMP_CD.Contains(search)));
        }

        // 載入篩選器可用選項 (動態載入現有不重複的 BG / BU)
        if (isGlobalAdmin)
        {
            AvailableBGs = await _userManager.Users.Where(u => u.BG != null).Select(u => u.BG!).Distinct().OrderBy(g => g).ToListAsync();
            AvailableBUs = await _userManager.Users.Where(u => u.BU != null).Select(u => u.BU!).Distinct().OrderBy(u => u).ToListAsync();
        }
        else if (isBgAdmin)
        {
            AvailableBGs = new List<string> { currentUser.BG ?? "" };
            AvailableBUs = await _userManager.Users.Where(u => u.BG == currentUser.BG && u.BU != null).Select(u => u.BU!).Distinct().OrderBy(u => u).ToListAsync();
        }

        var totalCount = await query.CountAsync();
        TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);

        var users = await query
            .OrderBy(u => u.UserName)
            .Skip((Page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        Users = new List<UserItem>();
        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            Users.Add(new UserItem
            {
                Id = user.Id,
                UserName = user.UserName ?? "",
                Email = user.Email,
                Roles = roles.ToList(),
                IsDisabled = user.LockoutEnabled && user.LockoutEnd > DateTimeOffset.UtcNow,
                BG = user.BG,
                BU = user.BU,
                EMP_CD = user.EMP_CD
            });
        }
    }

    public class UserItem
    {
        public string Id { get; set; } = "";
        public string UserName { get; set; } = "";
        public string? Email { get; set; }
        public List<string> Roles { get; set; } = new();
        public bool IsDisabled { get; set; }
        public string? BG { get; set; }
        public string? BU { get; set; }
        public string? EMP_CD { get; set; }
    }
}
