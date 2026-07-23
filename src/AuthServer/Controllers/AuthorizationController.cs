using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using AuthServer.Data;

namespace AuthServer.Controllers;

/// <summary>
/// OpenIddict 授權伺服器端點控制器
/// 處理授權碼流程、客戶端憑證流程、登出與使用者資訊
/// </summary>
[Route("connect")]
public class AuthorizationController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly ILogger<AuthorizationController> _logger;
    private readonly HybridCache _hybridCache;

    public AuthorizationController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IOpenIddictTokenManager tokenManager,
        ILogger<AuthorizationController> logger,
        HybridCache hybridCache)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenManager = tokenManager;
        _logger = logger;
        _hybridCache = hybridCache;
    }

    /// <summary>
    /// GET/POST /connect/authorize
    /// 授權碼流程入口：檢查使用者登入狀態，自動同意後頒發授權碼
    /// </summary>
    [HttpGet("authorize")]
    [HttpPost("authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("無法取得 OpenID Connect 請求。");

        // 使用者未登入 → 導向 Identity 登入頁面
        if (!User.Identity?.IsAuthenticated ?? true)
        {
            // prompt=none 但未登入時直接回傳錯誤，不前重新導向
            if (request.Prompt?.Contains("none", StringComparison.Ordinal) == true)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "使用者未登入。"
                    }));
            }

            // 儲存原始請求參數，登入完成後回到此頁面
            var redirectUri = Request.PathBase + Request.Path + QueryString.Create(
                Request.HasFormContentType
                    ? Request.Form.Select(p => KeyValuePair.Create(p.Key, (StringValues)p.Value))
                    : Request.Query.Select(p => KeyValuePair.Create(p.Key, (StringValues)p.Value)));

            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties { RedirectUri = redirectUri });
        }

        // 使用者已登入 — 自動同意（Auto-Consent），直接頒發授權碼
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ServerError,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "找不到使用者。"
                }));
        }

        // 為 OpenIddict 建立 principal，必須包含 sub (subject) claim
        var userClaims = new List<Claim>
        {
            new Claim(Claims.Subject, user.Id)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken),
            new Claim(Claims.PreferredUsername, user.UserName ?? user.Email ?? "unknown")
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken)
        };

        if (!string.IsNullOrEmpty(user.Email))
        {
            userClaims.Add(new Claim(Claims.Email, user.Email)
                .SetDestinations(Destinations.AccessToken));
        }

        var identity = new ClaimsIdentity(
            userClaims,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            Claims.Name,
            Claims.Role);

        var principal = new ClaimsPrincipal(identity);

        // 設定授權範圍與資源
        principal.SetScopes(request.GetScopes());
        principal.SetResources(await GetResourcesAsync(request.GetScopes()));

        _logger.LogInformation("用戶 {UserId} 請求授權碼 (Client={ClientId}, Scopes={Scopes})",
            user.Id, request.ClientId, string.Join(", ", request.GetScopes()));

        // 回傳授權碼（自動同意，跳過同意頁面）
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// POST /connect/token
    /// 處理三種授權流程：
    /// 1. authorization_code（含 PKCE）
    /// 2. refresh_token
    /// 3. client_credentials
    /// </summary>
    [HttpPost("token")]
    public async Task<IActionResult> Token()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("無法取得 OpenID Connect 請求。");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // ── 授權碼流程 或 刷新令牌流程 ──
            var principal = (await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal
                ?? throw new InvalidOperationException("無法驗證授權碼/刷新令牌。");

            // 從 principal 的 sub (subject) claim 提取使用者 ID
            var subject = principal.FindFirst(Claims.Subject)?.Value
                ?? principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(subject))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "無效的令牌請求。"
                    }));
            }

            var user = await _userManager.FindByIdAsync(subject);
            if (user == null)
            {
                _logger.LogWarning("Token 請求失敗: 找不到用戶 (Client={ClientId}, Subject={Subject})", request.ClientId, subject);
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "無效的令牌請求。"
                    }));
            }

            // 檢查使用者是否被鎖定
            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Token 請求失敗: 用戶已被鎖定 (Client={ClientId}, User={UserId})", request.ClientId, user.Id);
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "使用者帳號已被鎖定。"
                    }));
            }

            var newPrincipal = await _signInManager.CreateUserPrincipalAsync(user);

            // OpenIddict 需要明確的 subject claim
            var identity = (ClaimsIdentity)newPrincipal.Identity!;
            identity.AddClaim(new Claim(Claims.Subject, user.Id)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            newPrincipal.SetScopes(request.GetScopes());
            newPrincipal.SetResources(await GetResourcesAsync(request.GetScopes()));

            var grantType = request.IsAuthorizationCodeGrantType() ? "authorization_code" : "refresh_token";
            _logger.LogInformation("頒發 Token (GrantType={GrantType}, Client={ClientId}, User={UserId}, Scopes={Scopes})",
                grantType, request.ClientId, user.Id, string.Join(", ", request.GetScopes()));

            return SignIn(newPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsClientCredentialsGrantType())
        {
            // ── 客戶端憑證流程 ──
            var identity = new ClaimsIdentity(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // 客戶端身份
            var clientClaim = new Claim(Claims.Subject, request.ClientId ?? "unknown");
            clientClaim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
            identity.AddClaim(clientClaim);

            var nameClaim = new Claim(Claims.Name, request.ClientId ?? "unknown");
            nameClaim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
            identity.AddClaim(nameClaim);

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());
            principal.SetResources(await GetResourcesAsync(request.GetScopes()));

            _logger.LogInformation("頒發 ClientCredentials Token (Client={ClientId}, Scopes={Scopes})",
                request.ClientId, string.Join(", ", request.GetScopes()));

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        _logger.LogWarning("Token 請求失敗: 不支援的授權流程 (Client={ClientId}, GrantType={GrantType})",
            request.ClientId, request.GrantType);
        throw new InvalidOperationException("不支援的授權流程。");
    }

    /// <summary>
    /// GET/POST /connect/endsession
    /// SLO 層次 A：清除 Session Cookie + 撤銷該使用者的所有 Refresh Token
    /// </summary>
    [HttpGet("endsession")]
    [HttpPost("endsession")]
    public async Task<IActionResult> EndSession()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("無法取得 OpenID Connect 請求。");

        // SLO 層次 A：撤銷該使用者的所有 Refresh Token
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst(Claims.Subject)?.Value ?? "unknown";
        if (User.Identity?.IsAuthenticated == true)
        {
            var subject = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                ?? User.FindFirst(Claims.Subject)?.Value;
            if (subject != null)
            {
                // 使用 OpenIddict TokenManager 直接以 subject 條件撤銷所有 Refresh Token
                await _tokenManager.RevokeAsync(
                    subject: subject,
                    client: null,
                    type: TokenTypeHints.RefreshToken,
                    status: null,
                    cancellationToken: HttpContext.RequestAborted);
            }
        }

        _logger.LogInformation("用戶 {UserId} SLO 登出 (已撤銷 RefreshToken)", userId);

        // 登出 Identity Cookie
        await _signInManager.SignOutAsync();

        // 清除 OpenIddict 伺服器 Session
        await HttpContext.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // 如果有 post_logout_redirect_uri，重新導向回去
        if (!string.IsNullOrEmpty(request.PostLogoutRedirectUri))
        {
            return Redirect(request.PostLogoutRedirectUri);
        }

        return LocalRedirect("~/");
    }

    /// <summary>
    /// GET/POST /connect/userinfo
    /// 回傳 Access Token 對應的使用者資訊
    /// </summary>
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("userinfo")]
    [HttpPost("userinfo")]
    public async Task<IActionResult> UserInfo()
    {
        var principal = (await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal
            ?? throw new InvalidOperationException("無法驗證 Access Token。");

        _logger.LogInformation("UserInfo 請求 (Client={ClientId}, User={Subject})",
            principal.FindFirst(Claims.Subject)?.Value ?? "unknown",
            User.FindFirst(Claims.Subject)?.Value ?? "anonymous");

        // Client Credentials 流程 — 無對應使用者，僅回傳 client_id
        var subject = principal.FindFirst(Claims.Subject)?.Value;
        if (subject == null)
        {
            return Ok(new Dictionary<string, object>
            {
                [Claims.Subject] = "anonymous"
            });
        }

        // 🛡️ 使用 .NET 10 HybridCache 原子快取，確保高併發請求下只會有一次資料庫查詢 (Stampede Protection)
        var cachedUser = await _hybridCache.GetOrCreateAsync($"User_Claims_{subject}", async token =>
        {
            var dbUser = await _userManager.FindByIdAsync(subject);
            if (dbUser == null) return null!;

            var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(dbUser);
            return new CachedUserInfo(
                dbUser.Id,
                dbUser.UserName,
                dbUser.Email,
                isEmailConfirmed,
                dbUser.BG,
                dbUser.BU,
                dbUser.EMP_CD
            );
        });

        if (cachedUser == null)
        {
            // 可能是 client_credentials，回傳 client_id 資訊
            return Ok(new Dictionary<string, object>
            {
                [Claims.Subject] = subject,
                [Claims.Name] = subject
            });
        }

        var claims = new Dictionary<string, object>
        {
            [Claims.Subject] = cachedUser.Id
        };

        if (User.HasScope(Scopes.Profile))
        {
            if (!string.IsNullOrEmpty(cachedUser.UserName))
            {
                claims[Claims.PreferredUsername] = cachedUser.UserName;
            }
        }

        if (User.HasScope(Scopes.Email))
        {
            if (!string.IsNullOrEmpty(cachedUser.Email))
            {
                claims[Claims.Email] = cachedUser.Email;
                claims[Claims.EmailVerified] = cachedUser.IsEmailConfirmed;
            }
        }

        return Ok(claims);
    }

    public record CachedUserInfo(
        string Id,
        string? UserName,
        string? Email,
        bool IsEmailConfirmed,
        string? BG,
        string? BU,
        string? EMP_CD
    );

    /// <summary>
    /// 根據 Scope 解析資源名稱
    /// </summary>
    private static async Task<IEnumerable<string>> GetResourcesAsync(IEnumerable<string> scopes)
    {
        var resources = new List<string>();

        if (scopes.Contains("api", StringComparer.Ordinal))
        {
            resources.Add("resource-server");
        }

        await Task.CompletedTask;
        return resources;
    }
}
