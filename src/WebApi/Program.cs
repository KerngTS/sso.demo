using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Claims;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// ── JWT Bearer 驗證 ────────────────────────────────
// 從 AuthServer 取得 OIDC 配置（含公開金鑰）
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["AuthServer:Authority"] ?? "https://localhost:7138";
        options.Audience = "resource-server";
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters.ValidateIssuer = true;
        options.TokenValidationParameters.ValidIssuer = options.Authority;
        options.TokenValidationParameters.ValidateAudience = false; // Blazor 的 access_token 可能不含 aud
        options.TokenValidationParameters.ValidateLifetime = true;
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = "role";

        // 開發環境接受自簽憑證
        // options.BackchannelHttpHandler = new HttpClientHandler
        // {
        //     ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        // };
        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
            {
                var expectedThumbprint = builder.Configuration["AuthServer:ExpectedThumbprint"]?.Trim();

                // 如果有配置預期指紋，則優先且強制進行指紋比對 (Force Certificate Pinning)
                if (!string.IsNullOrEmpty(expectedThumbprint))
                {
                    if (cert != null)
                    {
                        // 根據配置指紋的長度動態選擇雜湊演算法：40字元為 SHA-1，64字元為 SHA-256
                        var algorithm = expectedThumbprint.Length == 40 ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
                        var actualThumbprint = cert.GetCertHashString(algorithm);

                        Console.WriteLine($"[Thumbprint Pinning] Algorithm: {algorithm.Name}");
                        Console.WriteLine($"[Thumbprint Pinning] Expected : {expectedThumbprint}");
                        Console.WriteLine($"[Thumbprint Pinning] Actual   : {actualThumbprint}");

                        if (string.Equals(actualThumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine($"[Thumbprint Pinning] 憑證指紋驗證成功！");
                            return true;
                        }
                        else
                        {
                            Console.WriteLine($"[Thumbprint Pinning] ⚠️ 憑證指紋不匹配，拒絕連線！");
                            return false;
                        }
                    }
                    Console.WriteLine($"[Thumbprint Pinning] ⚠️ 憑證為空，拒絕連線！");
                    return false;
                }

                // 如果沒有配置預期指紋，則退回到作業系統的受信任憑證鏈驗證
                if (sslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
                {
                    Console.WriteLine($"開發憑證通過作業系統驗證");
                    return true;
                }

                Console.WriteLine($"[Thumbprint Pinning] ⚠️ 未信任此憑證且未配置預期指紋，拒絕連線！SslPolicyErrors: {sslPolicyErrors}");
                return false;
            }
        };
    });

builder.Services.AddAuthorization();

// ── CORS（允許 Blazor WASM 呼叫）────────────────────
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services.AddOpenApi();

var app = builder.Build();

app.Use(async (context, next) =>
{
    var auth = context.Request.Headers.Authorization.FirstOrDefault() ?? "none";
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {context.Request.Method} {context.Request.Path} - Auth: {auth[..Math.Min(auth.Length, 80)]}");
    await next();
});

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// ── 公開端點（不需驗證）─────────────────────────────
app.MapGet("/", () => "Web API 資源伺服器執行中");

// ── 受保護的 API ──────────────────────────────────
app.MapGet("/api/weatherforecast", (HttpContext http) =>
{
    var userId = http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                 ?? http.User.FindFirst("sub")?.Value
                 ?? "anonymous";
    var userName = http.User.FindFirst("name")?.Value ?? userId;

    var summaries = new[] { "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching" };
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();

    return Results.Ok(new
    {
        User = userName,
        Forecast = forecast
    });
}).RequireAuthorization();

// ── 使用者資訊端點 ─────────────────────────────────
app.MapGet("/api/me", (HttpContext http) =>
{
    var claims = http.User.Claims.Select(c => new { c.Type, c.Value });
    return Results.Ok(claims);
}).RequireAuthorization();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
