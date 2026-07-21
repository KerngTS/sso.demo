using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
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

    public int UserCount { get; set; }
    public int RoleCount { get; set; }
    public int ClientCount { get; set; }
    public int ScopeCount { get; set; }

    public IndexModel(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOpenIddictApplicationManager appManager,
        IOpenIddictScopeManager scopeManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _appManager = appManager;
        _scopeManager = scopeManager;
    }

    public async Task OnGetAsync()
    {
        UserCount = await _userManager.Users.CountAsync();
        RoleCount = await _roleManager.Roles.CountAsync();

        var ct = 0;
        await foreach (var _ in _appManager.ListAsync()) ct++;
        ClientCount = ct;

        ct = 0;
        await foreach (var _ in _scopeManager.ListAsync()) ct++;
        ScopeCount = ct;
    }
}
