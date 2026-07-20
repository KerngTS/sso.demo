using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using BlazorWasm;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// ── OIDC 認證 ──────────────────────────────────────
// 向 AuthServer 進行 OpenID Connect 授權碼 + PKCE 流程
builder.Services.AddOidcAuthentication(options =>
{
    // 讀取 wwwroot/appsettings.json 中的設定
    builder.Configuration.Bind("Oidc", options.ProviderOptions);

    // 手動設定（與 appsettings.json 等效）
    options.ProviderOptions.Authority = "https://localhost:7138";
    options.ProviderOptions.ClientId = "blazor-wasm";
    options.ProviderOptions.ResponseType = "code";
    options.ProviderOptions.DefaultScopes.Clear();
    options.ProviderOptions.DefaultScopes.Add("openid");
    options.ProviderOptions.DefaultScopes.Add("profile");
    options.ProviderOptions.DefaultScopes.Add("api");
    options.ProviderOptions.DefaultScopes.Add("offline_access");
    options.ProviderOptions.RedirectUri = "http://localhost:5000/authentication/login-callback";
    options.ProviderOptions.PostLogoutRedirectUri = "http://localhost:5000/authentication/logout-callback";
});

// ── HTTP Client ─────────────────────────────────────
// 一般的 HttpClient（未經身份驗證）
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

// ── 帶 Token 的 HttpClient（用來呼叫 Web API）───
builder.Services.AddScoped<WebApiAuthorizationHandler>();
builder.Services.AddHttpClient("WebApi", client =>
{
    client.BaseAddress = new Uri("http://localhost:5001");
})
.AddHttpMessageHandler<WebApiAuthorizationHandler>();

await builder.Build().RunAsync();
