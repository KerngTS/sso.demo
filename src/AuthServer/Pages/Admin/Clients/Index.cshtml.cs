using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Hybrid;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Pages.Admin.Clients;

[Authorize(Roles = "admin,ClientManager")]
public class IndexModel : PageModel
{
    private readonly IOpenIddictApplicationManager _appManager;
    private readonly ILogger<IndexModel> _logger;
    private readonly HybridCache _hybridCache;

    public IndexModel(IOpenIddictApplicationManager appManager, ILogger<IndexModel> logger, HybridCache hybridCache)
    {
        _appManager = appManager;
        _logger = logger;
        _hybridCache = hybridCache;
    }

    public List<ClientItem> Clients { get; set; } = new();
    public new int Page { get; set; } = 1;
    public int TotalPages { get; set; } = 1;
    public string? Search { get; set; }

    public async Task OnGetAsync(string? search, int page = 1)
    {
        Search = search;
        Page = page < 1 ? 1 : page;
        const int pageSize = 10;
        var totalCount = 0;

        if (!string.IsNullOrWhiteSpace(search))
        {
            var searchTrim = search.Trim();
            var tempApps = new List<object>();

            // 🔍 搜尋模式：先遍歷獲取符合條件的應用程式 (在大數據下提供彈性，限制 N+1 只在當前分頁)
            await foreach (var app in _appManager.ListAsync())
            {
                var clientId = await _appManager.GetClientIdAsync(app) ?? "";
                var displayName = await _appManager.GetDisplayNameAsync(app) ?? "";
                if (clientId.Contains(searchTrim, StringComparison.OrdinalIgnoreCase) || 
                    displayName.Contains(searchTrim, StringComparison.OrdinalIgnoreCase))
                {
                    tempApps.Add(app);
                }
            }

            totalCount = tempApps.Count;
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
            if (Page > TotalPages && TotalPages > 0)
            {
                Page = TotalPages;
            }

            Clients = new List<ClientItem>();
            var pagedApps = tempApps.Skip((Page - 1) * pageSize).Take(pageSize);
            foreach (var app in pagedApps)
            {
                var perms = await _appManager.GetPermissionsAsync(app);

                Clients.Add(new ClientItem
                {
                    ClientId = (await _appManager.GetClientIdAsync(app)) ?? "",
                    DisplayName = await _appManager.GetDisplayNameAsync(app),
                    ClientType = await _appManager.GetClientTypeAsync(app) ?? "",
                    GrantTypes = string.Join(", ",
                        perms.Where(p => p.StartsWith(Permissions.Prefixes.GrantType))
                             .Select(p => p[Permissions.Prefixes.GrantType.Length..]))
                });
            }
        }
        else
        {
            // 📊 分頁計數 (只遍歷計數，無詳細欄位與權限子查詢，速度極快)
            await foreach (var app in _appManager.ListAsync())
            {
                totalCount++;
            }

            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
            if (Page > TotalPages && TotalPages > 0)
            {
                Page = TotalPages;
            }

            var offset = (Page - 1) * pageSize;
            Clients = new List<ClientItem>();

            // 🛡️ 安全防護：透過 count / offset 進行資料庫原生分頁，且僅對當前頁的 pageSize 筆資料進行詳細欄位與權限載入 (防止 N+1 風暴)
            await foreach (var app in _appManager.ListAsync(count: pageSize, offset: offset))
            {
                var perms = await _appManager.GetPermissionsAsync(app);

                Clients.Add(new ClientItem
                {
                    ClientId = (await _appManager.GetClientIdAsync(app)) ?? "",
                    DisplayName = await _appManager.GetDisplayNameAsync(app),
                    ClientType = await _appManager.GetClientTypeAsync(app) ?? "",
                    GrantTypes = string.Join(", ",
                        perms.Where(p => p.StartsWith(Permissions.Prefixes.GrantType))
                             .Select(p => p[Permissions.Prefixes.GrantType.Length..]))
                });
            }
        }
    }

    public async Task<IActionResult> OnGetDeleteAsync(string clientId)
    {
        var app = await _appManager.FindByClientIdAsync(clientId);
        if (app != null)
        {
            var displayName = await _appManager.GetDisplayNameAsync(app);
            _logger.LogWarning("管理員 {AdminUser} 刪除 Client {ClientId} ({DisplayName})", User.Identity?.Name, clientId, displayName);
            await _appManager.DeleteAsync(app);
            await _hybridCache.RemoveAsync("Dashboard_Stats");
        }
        return RedirectToPage();
    }

    public class ClientItem
    {
        public string ClientId { get; set; } = "";
        public string? DisplayName { get; set; }
        public string ClientType { get; set; } = "";
        public string GrantTypes { get; set; } = "";
    }
}
