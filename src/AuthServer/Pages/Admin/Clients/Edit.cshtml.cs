using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using System.Security.Cryptography;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Pages.Admin.Clients;

[Authorize(Roles = "admin,ClientManager")]
public class EditModel : PageModel
{
    private readonly IOpenIddictApplicationManager _appManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<EditModel> _logger;

    public EditModel(IOpenIddictApplicationManager appManager, IOpenIddictScopeManager scopeManager, ILogger<EditModel> logger)
    {
        _appManager = appManager;
        _scopeManager = scopeManager;
        _logger = logger;
    }

    [BindProperty]
    public ClientEditInput Input { get; set; } = new();

    [BindProperty]
    public List<string> SelectedScopes { get; set; } = new();

    public List<string> AvailableScopes { get; set; } = new();
    public string? ErrorMessage { get; set; }
    public string? ShowSecret { get; set; }

    public async Task<IActionResult> OnGetAsync(string clientId)
    {
        var app = await _appManager.FindByClientIdAsync(clientId);
        if (app == null) return NotFound();

        // Load available scopes
        AvailableScopes = new List<string>();
        // 🛡️ 安全上限限制：限制最多加載前 200 個 Scopes 複選框，防範 OOM
        await foreach (var scope in _scopeManager.ListAsync(count: 200, offset: 0))
        {
            var name = await _scopeManager.GetNameAsync(scope);
            if (name != null) AvailableScopes.Add(name);
        }

        var perms = new HashSet<string>(await _appManager.GetPermissionsAsync(app));
        var redirectUris = await _appManager.GetRedirectUrisAsync(app);
        var redirectUrisList = redirectUris.ToList();

        var logoutUris = await _appManager.GetPostLogoutRedirectUrisAsync(app);
        var logoutUrisList = logoutUris.ToList();

        Input = new ClientEditInput
        {
            OriginalClientId = clientId,
            ClientId = (await _appManager.GetClientIdAsync(app)) ?? clientId,
            DisplayName = await _appManager.GetDisplayNameAsync(app),
            ClientType = await _appManager.GetClientTypeAsync(app) ?? "",
            RedirectUris = string.Join('\n', redirectUrisList),
            PostLogoutRedirectUris = string.Join('\n', logoutUrisList),
            AllowAuthorizationCode = perms.Contains(Permissions.GrantTypes.AuthorizationCode),
            AllowClientCredentials = perms.Contains(Permissions.GrantTypes.ClientCredentials),
            AllowRefreshToken = perms.Contains(Permissions.GrantTypes.RefreshToken),
            Scopes = perms.Where(p => p.StartsWith(Permissions.Prefixes.Scope))
                          .Select(p => p[Permissions.Prefixes.Scope.Length..])
                          .ToList()
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        try
        {
            var app = await _appManager.FindByClientIdAsync(Input.OriginalClientId);
            if (app == null) return NotFound();

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = Input.OriginalClientId,
                DisplayName = Input.DisplayName,
                ClientType = Input.ClientType,
                ConsentType = ConsentTypes.Implicit
            };

            // Endpoints + Grants
            if (Input.AllowAuthorizationCode)
            {
                descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
                descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
                descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
                descriptor.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
            }
            if (Input.AllowClientCredentials)
            {
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
                descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
            }
            if (Input.AllowRefreshToken)
            {
                descriptor.Permissions.Add(Permissions.GrantTypes.RefreshToken);
            }

            // Scopes
            foreach (var scope in SelectedScopes)
                descriptor.Permissions.Add($"{Permissions.Prefixes.Scope}{scope}");

            // URIs
            if (!string.IsNullOrWhiteSpace(Input.RedirectUris))
            {
                foreach (var line in Input.RedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    if (Uri.TryCreate(line.Trim(), UriKind.Absolute, out var uri))
                        descriptor.RedirectUris.Add(uri);
            }

            if (!string.IsNullOrWhiteSpace(Input.PostLogoutRedirectUris))
            {
                foreach (var line in Input.PostLogoutRedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    if (Uri.TryCreate(line.Trim(), UriKind.Absolute, out var uri))
                        descriptor.PostLogoutRedirectUris.Add(uri);
            }

            // PKCE
            descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);

            await _appManager.UpdateAsync(app, descriptor);
            _logger.LogInformation("管理員 {AdminUser} 更新 Client {ClientId}", User.Identity?.Name, Input.OriginalClientId);
            return RedirectToPage("Index");
        }
        catch (Exception ex)
        {
            ErrorMessage = $"更新失敗：{ex.Message}";
            _logger.LogWarning("管理員 {AdminUser} 更新 Client {ClientId} 失敗: {Error}", User.Identity?.Name, Input.OriginalClientId, ex.Message);
            await ReloadScopesAsync();
            return Page();
        }
    }

    public async Task<IActionResult> OnPostRegenerateSecretAsync()
    {
        try
        {
            var app = await _appManager.FindByClientIdAsync(Input.OriginalClientId);
            if (app == null) return NotFound();

            var secretBytes = new byte[32];
            RandomNumberGenerator.Fill(secretBytes);
            var newSecret = Convert.ToBase64String(secretBytes);

            var descriptor = new OpenIddictApplicationDescriptor { ClientId = Input.OriginalClientId };
            descriptor.ClientSecret = newSecret;

            await _appManager.UpdateAsync(app, descriptor);
            _logger.LogWarning("管理員 {AdminUser} 重新生成 Client {ClientId} 密鑰", User.Identity?.Name, Input.OriginalClientId);
            ShowSecret = newSecret;

            // Re-populate the form
            await LoadFormDataAsync(Input.OriginalClientId);
            return Page();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"重新產生 Secret 失敗：{ex.Message}";
            await LoadFormDataAsync(Input.OriginalClientId);
            return Page();
        }
    }

    private async Task LoadFormDataAsync(string clientId)
    {
        // Reload available scopes
        AvailableScopes = new List<string>();
        // 🛡️ 安全上限限制：限制最多加載前 200 個 Scopes 複選框，防範 OOM
        await foreach (var scope in _scopeManager.ListAsync(count: 200, offset: 0))
        {
            var name = await _scopeManager.GetNameAsync(scope);
            if (name != null) AvailableScopes.Add(name);
        }
    }

    private async Task ReloadScopesAsync()
    {
        AvailableScopes = new List<string>();
        // 🛡️ 安全上限限制：限制最多加載前 200 個 Scopes 複選框，防範 OOM
        await foreach (var scope in _scopeManager.ListAsync(count: 200, offset: 0))
        {
            var name = await _scopeManager.GetNameAsync(scope);
            if (name != null) AvailableScopes.Add(name);
        }
    }

    public class ClientEditInput
    {
        public string OriginalClientId { get; set; } = "";
        public string ClientId { get; set; } = "";
        public string? DisplayName { get; set; }
        public string ClientType { get; set; } = "";
        public string? RedirectUris { get; set; }
        public string? PostLogoutRedirectUris { get; set; }
        public bool AllowAuthorizationCode { get; set; }
        public bool AllowClientCredentials { get; set; }
        public bool AllowRefreshToken { get; set; }
        public List<string> Scopes { get; set; } = new();
    }
}
