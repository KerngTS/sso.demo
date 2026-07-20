using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Pages.Admin.Clients;

[Authorize(Roles = "admin,ClientManager")]
public class IndexModel : PageModel
{
    private readonly IOpenIddictApplicationManager _appManager;
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(IOpenIddictApplicationManager appManager, ILogger<IndexModel> logger)
    {
        _appManager = appManager;
        _logger = logger;
    }

    public List<ClientItem> Clients { get; set; } = new();

    public async Task OnGetAsync()
    {
        Clients = new List<ClientItem>();
        await foreach (var app in _appManager.ListAsync())
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

    public async Task<IActionResult> OnGetDeleteAsync(string clientId)
    {
        var app = await _appManager.FindByClientIdAsync(clientId);
        if (app != null)
        {
            var displayName = await _appManager.GetDisplayNameAsync(app);
            _logger.LogWarning("管理員 {AdminUser} 刪除 Client {ClientId} ({DisplayName})", User.Identity?.Name, clientId, displayName);
            await _appManager.DeleteAsync(app);
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
