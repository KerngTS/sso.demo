using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using AuthServer.Data;
using AuthServer.Pages.Admin.Roles;
using Xunit;

namespace AuthServer.Tests;

public class RolesPageTests
{
    private DbContextOptions<ApplicationDbContext> CreateNewInMemoryDatabaseOptions()
    {
        return new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString()) // 確保每次測試資料庫完全獨立隔離
            .Options;
    }

    [Fact]
    public async Task OnGetAsync_ShouldLoadAllRolesInDb_WhenNoSearchAndPageIsOne()
    {
        // Arrange
        var options = CreateNewInMemoryDatabaseOptions();
        using var context = new ApplicationDbContext(options);

        // Seed 3 Roles
        context.Roles.Add(new IdentityRole { Id = "r1", Name = "admin" });
        context.Roles.Add(new IdentityRole { Id = "r2", Name = "UserManager" });
        context.Roles.Add(new IdentityRole { Id = "r3", Name = "ClientManager" });
        await context.SaveChangesAsync();

        var indexModel = new IndexModel(null!, null!, context, NullLogger<IndexModel>.Instance, null!);

        // Act
        await indexModel.OnGetAsync(search: null, page: 1);

        // Assert
        Assert.Equal(3, indexModel.Roles.Count);
        Assert.Equal(1, indexModel.TotalPages);
        Assert.Equal(1, indexModel.Page);
        Assert.Equal("admin", indexModel.Roles[0].Name);
        Assert.Equal("ClientManager", indexModel.Roles[1].Name); // OrderBy(r => r.Name) => ClientManager, UserManager, admin
    }

    [Fact]
    public async Task OnGetAsync_ShouldCorrectlyCalculateUserCounts_ViaGroupJoin()
    {
        // Arrange
        var options = CreateNewInMemoryDatabaseOptions();
        using var context = new ApplicationDbContext(options);

        // Seed Roles
        context.Roles.Add(new IdentityRole { Id = "role-admin", Name = "admin" });
        context.Roles.Add(new IdentityRole { Id = "role-user", Name = "user" });

        // Seed User-Role mappings (3 in admin, 1 in user)
        context.UserRoles.Add(new IdentityUserRole<string> { UserId = "u1", RoleId = "role-admin" });
        context.UserRoles.Add(new IdentityUserRole<string> { UserId = "u2", RoleId = "role-admin" });
        context.UserRoles.Add(new IdentityUserRole<string> { UserId = "u3", RoleId = "role-admin" });
        context.UserRoles.Add(new IdentityUserRole<string> { UserId = "u4", RoleId = "role-user" });
        await context.SaveChangesAsync();

        var indexModel = new IndexModel(null!, null!, context, NullLogger<IndexModel>.Instance, null!);

        // Act
        await indexModel.OnGetAsync(search: null, page: 1);

        // Assert
        var adminRole = indexModel.Roles.FirstOrDefault(r => r.Name == "admin");
        var userRole = indexModel.Roles.FirstOrDefault(r => r.Name == "user");

        Assert.NotNull(adminRole);
        Assert.Equal(3, adminRole!.UserCount);

        Assert.NotNull(userRole);
        Assert.Equal(1, userRole!.UserCount);
    }

    [Fact]
    public async Task OnGetAsync_ShouldFilterRoles_WhenSearchKeywordIsProvided()
    {
        // Arrange
        var options = CreateNewInMemoryDatabaseOptions();
        using var context = new ApplicationDbContext(options);

        context.Roles.Add(new IdentityRole { Id = "r1", Name = "admin" });
        context.Roles.Add(new IdentityRole { Id = "r2", Name = "UserManager" });
        context.Roles.Add(new IdentityRole { Id = "r3", Name = "ClientManager" });
        await context.SaveChangesAsync();

        var indexModel = new IndexModel(null!, null!, context, NullLogger<IndexModel>.Instance, null!);

        // Act
        await indexModel.OnGetAsync(search: "Manager", page: 1);

        // Assert
        Assert.Equal(2, indexModel.Roles.Count);
        Assert.True(indexModel.Roles.All(r => r.Name.Contains("Manager")));
    }

    [Fact]
    public async Task OnGetAsync_ShouldPaginateCorrectly_AndAdjustBoundaryPages()
    {
        // Arrange
        var options = CreateNewInMemoryDatabaseOptions();
        using var context = new ApplicationDbContext(options);

        // Seed 15 Roles
        for (int i = 1; i <= 15; i++)
        {
            context.Roles.Add(new IdentityRole { Id = $"r{i}", Name = $"Role_{i:D2}" });
        }
        await context.SaveChangesAsync();

        var indexModel = new IndexModel(null!, null!, context, NullLogger<IndexModel>.Instance, null!);

        // Act 1: Page 1 (Expected 10 items)
        await indexModel.OnGetAsync(search: null, page: 1);
        Assert.Equal(10, indexModel.Roles.Count);
        Assert.Equal(2, indexModel.TotalPages);

        // Act 2: Page 2 (Expected 5 items)
        await indexModel.OnGetAsync(search: null, page: 2);
        Assert.Equal(5, indexModel.Roles.Count);

        // Act 3: Negative Page Boundary Adjustment
        await indexModel.OnGetAsync(search: null, page: -10);
        Assert.Equal(1, indexModel.Page); // Should automatically correct to Page 1
        Assert.Equal(10, indexModel.Roles.Count);

        // Act 4: Out of bounds Page Boundary Adjustment
        await indexModel.OnGetAsync(search: null, page: 9999);
        Assert.Equal(2, indexModel.Page); // Should automatically correct to Max Page (2)
        Assert.Equal(5, indexModel.Roles.Count);
    }
}
