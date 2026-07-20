using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using System.Globalization;
using System.Security.Cryptography;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Data;

/// <summary>
/// 資料庫種子資料初始化
/// 建立預設客戶端應用程式與 Scope
/// </summary>
public static class SeedData
{
    public static async Task InitializeAsync(IServiceProvider serviceProvider)
    {
        var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();
        var logger = loggerFactory.CreateLogger("AuthServer.Data.SeedData");

        await CreateScopesAsync(serviceProvider, logger);
        await CreateApplicationsAsync(serviceProvider, logger);
        await CreateAdminUserAsync(serviceProvider, logger);
    }

    private static async Task CreateScopesAsync(IServiceProvider serviceProvider, ILogger logger)
    {
        var scopeManager = serviceProvider.GetRequiredService<IOpenIddictScopeManager>();

        foreach (var scope in new[] { "api", Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Roles, "offline_access" })
        {
            if (await scopeManager.FindByNameAsync(scope) is null)
            {
                var descriptor = new OpenIddictScopeDescriptor
                {
                    Name = scope,
                    DisplayName = scope switch
                    {
                        "api" => "API 存取",
                        "offline_access" => "離線存取 (Refresh Token)",
                        _ when scope == Scopes.OpenId => "OpenID Connect 身份驗證",
                        _ when scope == Scopes.Profile => "使用者個人資料",
                        _ when scope == Scopes.Email => "電子郵件地址",
                        _ when scope == Scopes.Roles => "使用者角色",
                        _ => scope
                    }
                };

                if (scope == "api")
                {
                    descriptor.Resources.Add("resource-server");
                }

                await scopeManager.CreateAsync(descriptor);
                logger.LogInformation("種子資料: 創建 Scope {ScopeName}", scope);
            }
        }
    }

    private static async Task CreateApplicationsAsync(IServiceProvider serviceProvider, ILogger logger)
    {
        var applicationManager = serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // ── Blazor WASM 公開客戶端 ──
        if (await applicationManager.FindByClientIdAsync("blazor-wasm") is null)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "blazor-wasm",
                ClientType = OpenIddictConstants.ClientTypes.Public,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                DisplayName = "Blazor WebAssembly 應用程式",
                DisplayNames =
                {
                    [new CultureInfo("zh-TW")] = "Blazor WebAssembly 應用程式"
                },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,

                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                    OpenIddictConstants.Permissions.ResponseTypes.Code,

                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,

                    $"{Permissions.Prefixes.Scope}{Scopes.OpenId}",
                    $"{Permissions.Prefixes.Scope}api",
                    $"{Permissions.Prefixes.Scope}offline_access"
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                }
            };

            descriptor.RedirectUris.Add(new Uri("http://localhost:5000/authentication/login-callback"));
            descriptor.RedirectUris.Add(new Uri("https://localhost:5001/authentication/login-callback"));
            descriptor.PostLogoutRedirectUris.Add(new Uri("http://localhost:5000/authentication/logout-callback"));
            descriptor.PostLogoutRedirectUris.Add(new Uri("https://localhost:5001/authentication/logout-callback"));

            await applicationManager.CreateAsync(descriptor);
            logger.LogInformation("種子資料: 創建 Client {ClientId} (Type=Public)", "blazor-wasm");
        }

        // ── .NET Web API 機密客戶端 ──
        if (await applicationManager.FindByClientIdAsync("dotnet-webapi") is null)
        {
            using var rng = RandomNumberGenerator.Create();
            var secretBytes = new byte[32];
            rng.GetBytes(secretBytes);
            var clientSecret = Convert.ToBase64String(secretBytes);

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "dotnet-webapi",
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                DisplayName = ".NET Web API",
                DisplayNames =
                {
                    [new CultureInfo("zh-TW")] = ".NET Web API"
                },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token,

                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,

                    $"{OpenIddictConstants.Permissions.Prefixes.Scope}api"
                }
            };

            descriptor.ClientSecret = clientSecret;

            await applicationManager.CreateAsync(descriptor);

            logger.LogInformation("種子資料: 創建 Client {ClientId} (Type=Confidential)", "dotnet-webapi");
        }
    }

    private static async Task CreateAdminUserAsync(IServiceProvider serviceProvider, ILogger logger)
    {
        var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        // 建立所有管理角色
        foreach (var roleName in new[] { "admin", "UserManager", "ClientManager", "ScopeManager" })
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new IdentityRole(roleName));
                logger.LogInformation("種子資料: 創建角色 {RoleName}", roleName);
            }
        }

        const string adminEmail = "admin@sso.local";
        if (await userManager.FindByEmailAsync(adminEmail) is null)
        {
            var admin = new IdentityUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(admin, "Admin123!");
            if (result.Succeeded)
            {
                // 將 admin 用戶加入所有管理角色
                await userManager.AddToRolesAsync(admin,
                    new[] { "admin", "UserManager", "ClientManager", "ScopeManager" });
                logger.LogInformation("種子資料: 創建管理員 {Email} (角色: admin, UserManager, ClientManager, ScopeManager)", adminEmail);
            }
        }
    }
}
