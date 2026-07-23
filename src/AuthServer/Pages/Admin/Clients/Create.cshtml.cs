using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Hybrid;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Pages.Admin.Clients;

[Authorize(Roles = "admin,ClientManager")]
public class CreateModel : PageModel
{
    private readonly IOpenIddictApplicationManager _appManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<CreateModel> _logger;
    private readonly HybridCache _hybridCache;

    public CreateModel(
        IOpenIddictApplicationManager appManager, 
        IOpenIddictScopeManager scopeManager, 
        ILogger<CreateModel> logger,
        HybridCache hybridCache)
    {
        _appManager = appManager;
        _scopeManager = scopeManager;
        _logger = logger;
        _hybridCache = hybridCache;
    }

    [BindProperty]
    public ClientInput Input { get; set; } = new();

    [BindProperty]
    public List<string> SelectedScopes { get; set; } = new();

    public List<string> AvailableScopes { get; set; } = new();

    public string? ErrorMessage { get; set; }
    public string? GeneratedSecret { get; set; }

    public async Task OnGetAsync()
    {
        AvailableScopes = new List<string>();
        // 🛡️ 安全上限限制：限制最多加載前 200 個 Scopes 複選框，防止在大數據量下造成加載卡頓或 OOM
        await foreach (var scope in _scopeManager.ListAsync(count: 200, offset: 0))
        {
            var name = await _scopeManager.GetNameAsync(scope);
            if (name != null) AvailableScopes.Add(name);
        }
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();

        try
        {
            var existing = await _appManager.FindByClientIdAsync(Input.ClientId);
            if (existing != null)
            {
                ErrorMessage = $"ClientId '{Input.ClientId}' 已存在。";
                _logger.LogWarning("管理員 {AdminUser} 創建 Client 失敗: {ClientId} 已存在", User.Identity?.Name, Input.ClientId);
                await ReloadScopesAsync();
                return Page();
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = Input.ClientId,
                DisplayName = Input.DisplayName,
                ClientType = Input.ClientType,
                ConsentType = ConsentTypes.Implicit
            };

            // Endpoints
            if (Input.AllowAuthorizationCode)
            {
                descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
                descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
                descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
            }
            if (Input.AllowClientCredentials)
            {
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
            }
            if (Input.AllowRefreshToken)
            {
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
                descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
            }

            // Grant Types
            if (Input.AllowAuthorizationCode)
                descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
            if (Input.AllowClientCredentials)
                descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
            // RefreshToken already added above

            // Scopes
            foreach (var scope in SelectedScopes)
            {
                descriptor.Permissions.Add($"{Permissions.Prefixes.Scope}{scope}");
            }

            // Requirements
            if (Input.RequirePkce)
                descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);

            // Redirect URIs
            if (!string.IsNullOrWhiteSpace(Input.RedirectUris))
            {
                foreach (var line in Input.RedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (Uri.TryCreate(line.Trim(), UriKind.Absolute, out var uri))
                        descriptor.RedirectUris.Add(uri);
                }
            }

            // Post-logout URIs
            if (!string.IsNullOrWhiteSpace(Input.PostLogoutRedirectUris))
            {
                foreach (var line in Input.PostLogoutRedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (Uri.TryCreate(line.Trim(), UriKind.Absolute, out var uri))
                        descriptor.PostLogoutRedirectUris.Add(uri);
                }
            }

            // 機密客戶端產生 Secret
            if (Input.ClientType == ClientTypes.Confidential)
            {
                var secretBytes = new byte[32];
                RandomNumberGenerator.Fill(secretBytes);
                GeneratedSecret = Convert.ToBase64String(secretBytes);
                descriptor.ClientSecret = GeneratedSecret;
            }

            await _appManager.CreateAsync(descriptor);

            // 🛡️ 創建成功主動清除統計快取
            await _hybridCache.RemoveAsync("Dashboard_Stats");

            _logger.LogInformation("管理員 {AdminUser} 創建 Client {ClientId} (Type={ClientType})", User.Identity?.Name, Input.ClientId, Input.ClientType);

            if (GeneratedSecret != null)
            {
                TempData["ClientSecret"] = GeneratedSecret;
                TempData["ClientId"] = Input.ClientId;
            }

            return RedirectToPage("Index");
        }
        catch (Exception ex)
        {
            ErrorMessage = $"建立失敗：{ex.Message}";
            _logger.LogWarning("管理員 {AdminUser} 創建 Client 失敗: {Error}", User.Identity?.Name, ex.Message);
            await ReloadScopesAsync();
            return Page();
        }
    }

    private async Task ReloadScopesAsync()
    {
        AvailableScopes = new List<string>();
        // 🛡️ 安全上限限制：限制最多加載前 200 個 Scopes，防止在建立失敗重新載入時造成 OOM
        await foreach (var scope in _scopeManager.ListAsync(count: 200, offset: 0))
        {
            var name = await _scopeManager.GetNameAsync(scope);
            if (name != null) AvailableScopes.Add(name);
        }
    }

    public class ClientInput
    {
        [Required(ErrorMessage = "ClientId 為必填")]
        public string ClientId { get; set; } = "";

        public string? DisplayName { get; set; }
        public string ClientType { get; set; } = ClientTypes.Public;

        public string? RedirectUris { get; set; }
        public string? PostLogoutRedirectUris { get; set; }

        public bool AllowAuthorizationCode { get; set; } = true;
        public bool AllowClientCredentials { get; set; }
        public bool AllowRefreshToken { get; set; } = true;
        public bool RequirePkce { get; set; } = true;
    }
}
