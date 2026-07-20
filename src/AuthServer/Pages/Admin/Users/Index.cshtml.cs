using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Pages.Admin.Users;

[Authorize(Roles = "admin,UserManager")]
public class IndexModel : PageModel
{
    private readonly UserManager<IdentityUser> _userManager;

    public IndexModel(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager;
    }

    public List<UserItem> Users { get; set; } = new();
    public int Page { get; set; } = 1;
    public int TotalPages { get; set; } = 1;
    public string? Search { get; set; }

    public async Task OnGetAsync(string? search, int page = 1)
    {
        Search = search;
        Page = page < 1 ? 1 : page;
        const int pageSize = 10;

        var query = _userManager.Users.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            search = search.Trim();
            query = query.Where(u => (u.UserName != null && u.UserName.Contains(search))
                                  || (u.Email != null && u.Email.Contains(search)));
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
                IsDisabled = user.LockoutEnabled && user.LockoutEnd > DateTimeOffset.UtcNow
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
    }
}
