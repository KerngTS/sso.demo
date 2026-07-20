using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Claims;

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
        options.BackchannelHttpHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
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
