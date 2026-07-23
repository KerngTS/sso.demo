using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Hybrid;
using Moq;
using OpenIddict.Abstractions;
using AuthServer.Data;
using AuthServer.Pages;
using Xunit;

namespace AuthServer.Tests;

public class DashboardTests
{
    private DbContextOptions<ApplicationDbContext> CreateInMemoryDbOptions()
    {
        return new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
    }

    [Fact]
    public async Task OnGetAsync_ShouldLoadCountsFromDatabaseAndOpenIddict()
    {
        // Arrange
        var options = CreateInMemoryDbOptions();
        using var context = new ApplicationDbContext(options);

        // Seed 2 Users
        context.Users.Add(new ApplicationUser { Id = "u1", UserName = "admin@sso.local", Email = "admin@sso.local" });
        context.Users.Add(new ApplicationUser { Id = "u2", UserName = "user@sso.local", Email = "user@sso.local" });

        // Seed 3 Roles
        context.Roles.Add(new IdentityRole { Id = "r1", Name = "admin", NormalizedName = "ADMIN" });
        context.Roles.Add(new IdentityRole { Id = "r2", Name = "UserManager", NormalizedName = "USERMANAGER" });
        context.Roles.Add(new IdentityRole { Id = "r3", Name = "ClientManager", NormalizedName = "CLIENTMANAGER" });
        await context.SaveChangesAsync();

        // Instantiate real UserManager and RoleManager with InMemory DB
        var userStore = new Microsoft.AspNetCore.Identity.EntityFrameworkCore.UserStore<ApplicationUser>(context);
        var userManager = new UserManager<ApplicationUser>(userStore, null!, new PasswordHasher<ApplicationUser>(), null!, null!, null!, null!, null!, null!);

        var roleStore = new Microsoft.AspNetCore.Identity.EntityFrameworkCore.RoleStore<IdentityRole>(context);
        var roleManager = new RoleManager<IdentityRole>(roleStore, null!, null!, null!, null!);

        // Mock OpenIddict App & Scope managers to return specific counts
        var mockAppManager = new Mock<IOpenIddictApplicationManager>();
        mockAppManager.Setup(m => m.CountAsync(It.IsAny<CancellationToken>())).ReturnsAsync(8);

        var mockScopeManager = new Mock<IOpenIddictScopeManager>();
        mockScopeManager.Setup(m => m.CountAsync(It.IsAny<CancellationToken>())).ReturnsAsync(15);

        // Use our clean custom TestHybridCache instead of Moq
        var testCache = new TestHybridCache();

        var dashboardModel = new IndexModel(userManager, roleManager, mockAppManager.Object, mockScopeManager.Object, testCache);

        // Act
        await dashboardModel.OnGetAsync();

        // Assert
        Assert.Equal(2, dashboardModel.UserCount);     // From SQLite / InMemory DB
        Assert.Equal(3, dashboardModel.RoleCount);     // From SQLite / InMemory DB
        Assert.Equal(8, dashboardModel.ClientCount);   // From OpenIddict Mocked CountAsync
        Assert.Equal(15, dashboardModel.ScopeCount);  // From OpenIddict Mocked CountAsync

        // Ensure CountAsync was invoked exactly once (Verifying Ticket #01: O(1) optimization)
        mockAppManager.Verify(m => m.CountAsync(It.IsAny<CancellationToken>()), Times.Once);
        mockScopeManager.Verify(m => m.CountAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>
    /// 🛡️ 實作自訂 TestHybridCache 樁，避開 Moq 對於 HybridCache 非虛擬成員的攔截限制
    /// </summary>
    private class TestHybridCache : HybridCache
    {
        public override async ValueTask<T> GetOrCreateAsync<TState, T>(
            string key,
            TState state,
            Func<TState, CancellationToken, ValueTask<T>> factory,
            HybridCacheEntryOptions? options = null,
            IEnumerable<string>? tags = null,
            CancellationToken cancellationToken = default)
        {
            // 測試環境下直接呼叫數據工廠委派，不進行快取序列化
            return await factory(state, cancellationToken);
        }

        public override ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default)
        {
            return ValueTask.CompletedTask;
        }

        public override ValueTask RemoveAsync(IEnumerable<string> keys, CancellationToken cancellationToken = default)
        {
            return ValueTask.CompletedTask;
        }

        public override ValueTask RemoveByTagAsync(string tag, CancellationToken cancellationToken = default)
        {
            return ValueTask.CompletedTask;
        }

        public override ValueTask RemoveByTagAsync(IEnumerable<string> tags, CancellationToken cancellationToken = default)
        {
            return ValueTask.CompletedTask;
        }

        public override ValueTask SetAsync<T>(
            string key,
            T value,
            HybridCacheEntryOptions? options = null,
            IEnumerable<string>? tags = null,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.CompletedTask;
        }
    }
}
