using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Hybrid;
using OpenIddict.Abstractions;

namespace AuthServer.Pages.Admin.Scopes;

[Authorize(Roles = "admin,ScopeManager")]
public class IndexModel : PageModel
{
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<IndexModel> _logger;
    private readonly HybridCache _hybridCache;

    public IndexModel(IOpenIddictScopeManager scopeManager, ILogger<IndexModel> logger, HybridCache hybridCache)
    {
        _scopeManager = scopeManager;
        _logger = logger;
        _hybridCache = hybridCache;
    }

    public List<ScopeItem> Scopes { get; set; } = new();
    public string? ErrorMessage { get; set; }
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
            var tempScopes = new List<object>();

            // 🔍 搜尋模式：先篩選符合關鍵字的 Scope
            await foreach (var scope in _scopeManager.ListAsync())
            {
                var name = await _scopeManager.GetNameAsync(scope) ?? "";
                var displayName = await _scopeManager.GetDisplayNameAsync(scope) ?? "";
                if (name.Contains(searchTrim, StringComparison.OrdinalIgnoreCase) ||
                    displayName.Contains(searchTrim, StringComparison.OrdinalIgnoreCase))
                {
                    tempScopes.Add(scope);
                }
            }

            totalCount = tempScopes.Count;
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
            if (Page > TotalPages && TotalPages > 0)
            {
                Page = TotalPages;
            }

            Scopes = new List<ScopeItem>();
            var pagedScopes = tempScopes.Skip((Page - 1) * pageSize).Take(pageSize);
            foreach (var scope in pagedScopes)
            {
                Scopes.Add(new ScopeItem
                {
                    Name = (await _scopeManager.GetNameAsync(scope)) ?? "",
                    DisplayName = await _scopeManager.GetDisplayNameAsync(scope),
                    Description = await _scopeManager.GetDescriptionAsync(scope),
                    Resources = string.Join(", ", (await _scopeManager.GetResourcesAsync(scope)))
                });
            }
        }
        else
        {
            // 📊 僅對 Scope 總數進行計數 (無額外資源加載子查詢，速度極快)
            await foreach (var scope in _scopeManager.ListAsync())
            {
                totalCount++;
            }

            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
            if (Page > TotalPages && TotalPages > 0)
            {
                Page = TotalPages;
            }

            var offset = (Page - 1) * pageSize;
            Scopes = new List<ScopeItem>();

            // 🛡️ 安全防護：透過 count / offset 進行資料庫原生分頁，且僅對當前頁的資料進行資源解析 (防範 OOM 與 N+1 過載)
            await foreach (var scope in _scopeManager.ListAsync(count: pageSize, offset: offset))
            {
                Scopes.Add(new ScopeItem
                {
                    Name = (await _scopeManager.GetNameAsync(scope)) ?? "",
                    DisplayName = await _scopeManager.GetDisplayNameAsync(scope),
                    Description = await _scopeManager.GetDescriptionAsync(scope),
                    Resources = string.Join(", ", (await _scopeManager.GetResourcesAsync(scope)))
                });
            }
        }
    }

    public async Task<IActionResult> OnGetDeleteAsync(string name)
    {
        var scope = await _scopeManager.FindByNameAsync(name);
        if (scope != null)
        {
            _logger.LogWarning("管理員 {AdminUser} 刪除 Scope {ScopeName}", User.Identity?.Name, name);
            await _scopeManager.DeleteAsync(scope);
            await _hybridCache.RemoveAsync("Dashboard_Stats");
        }
        return RedirectToPage();
    }

    public class ScopeItem
    {
        public string Name { get; set; } = "";
        public string? DisplayName { get; set; }
        public string? Description { get; set; }
        public string? Resources { get; set; }
    }
}
