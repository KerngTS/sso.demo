using System.Security.Cryptography.X509Certificates;
using AuthServer.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Quartz;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console(outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {SourceContext} — {Message:lj}{NewLine}{Exception}")
    .CreateBootstrapLogger();

var builder = WebApplication.CreateBuilder(args);

// ── Serilog ────────────────────────────────────────────
builder.Host.UseSerilog((context, loggerConfig) =>
    loggerConfig.ReadFrom.Configuration(context.Configuration));

// ── Database ──────────────────────────────────────────
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

// ── ASP.NET Core Identity ─────────────────────────────
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // 帳號鎖定設定
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;

    // 密碼原則
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 6;

    // 註冊設定
    options.SignIn.RequireConfirmedAccount = false;
    options.SignIn.RequireConfirmedEmail = false;
    options.SignIn.RequireConfirmedPhoneNumber = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddDefaultUI();

// Cookie 設定（登入/登出重新導向）
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
});

// ── OpenIddict ────────────────────────────────────────
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();

        // 使用 Quartz 定期清理過期 Token
        options.UseQuartz();
    })
    .AddServer(options =>
    {
        // 開發階段使用暫時性的加密與簽章金鑰（正式環境應改用憑證）
// #if DEBUG
//         options.AddEphemeralEncryptionKey()
//                .AddEphemeralSigningKey();
// #else
//         var certPath = builder.Configuration["Certificates:Path"] ?? "sso-cert.pfx";
//         var certPassword = builder.Configuration["Certificates:Password"] ?? "YourPassword";
//         var tokenCertificate = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.EphemeralKeySet);

//         options.AddSigningCertificate(tokenCertificate)
//                .AddEncryptionCertificate(tokenCertificate);
// #endif
        var certPath = builder.Configuration["Certificates:Path"] ?? "sso-cert.pfx";
        if (!Path.IsPathRooted(certPath))
        {
            certPath = Path.Combine(AppContext.BaseDirectory, certPath);
        }
        var certPassword = builder.Configuration["Certificates:Password"] ?? "YourPassword";
        var tokenCertificate = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.EphemeralKeySet);

        options.AddSigningCertificate(tokenCertificate)
               .AddEncryptionCertificate(tokenCertificate);
        

        // 端點路徑
        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token")
               .SetEndSessionEndpointUris("connect/endsession")
               .SetUserInfoEndpointUris("connect/userinfo");

        // 授權流程
        options.AllowAuthorizationCodeFlow()     // 授權碼 + PKCE
               .AllowClientCredentialsFlow()     // 客戶端憑證
               .AllowRefreshTokenFlow();         // 刷新令牌

        // Token 生命週期
        options.SetAccessTokenLifetime(TimeSpan.FromHours(1))
               .SetRefreshTokenLifetime(TimeSpan.FromDays(14))
               .SetRefreshTokenReuseLeeway(TimeSpan.FromSeconds(30));

        // 不加密 Access Token（讓資源伺服器可自行驗證）
        options.DisableAccessTokenEncryption();

        // 註冊 Scope
        options.RegisterScopes("api", "openid", "profile", "email", "roles", "offline_access");

        // ASP.NET Core 整合 — 使用 Passthrough 模式
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough();
    });

// ── Quartz（OpenIddict Token 清理背景作業）───────────
builder.Services.AddQuartz();
builder.Services.AddQuartzHostedService(options =>
{
    options.WaitForJobsToComplete = true;
});

// ── Controllers（OpenIddict 端點）──────────────────────
builder.Services.AddControllers();

// ── Razor Pages（Identity UI + 應用頁面）───────────────
builder.Services.AddRazorPages();

// ── CORS ──────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

// ── HTTP 管線 ────────────────────────────────────────
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseSerilogRequestLogging();

app.UseRouting();

app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapControllers();
app.MapRazorPages()
   .WithStaticAssets();

// ── 資料庫遷移與種子資料 ────────────────────────────
#if DEBUG
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

    if (context.Database.GetPendingMigrations().Any())
    {
        context.Database.Migrate();
    }

    await SeedData.InitializeAsync(scope.ServiceProvider);
}
#endif

app.Run();
