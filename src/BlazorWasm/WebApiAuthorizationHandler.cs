using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;

namespace BlazorWasm;

/// <summary>
/// 自訂授權處理器 — 在呼叫 Web API 時自動附加 Access Token
/// </summary>
public class WebApiAuthorizationHandler : AuthorizationMessageHandler
{
    public WebApiAuthorizationHandler(IAccessTokenProvider provider, NavigationManager navigation)
        : base(provider, navigation)
    {
        ConfigureHandler(
            authorizedUrls: new[] { "http://localhost:5001" },
            scopes: new[] { "api" });
    }
}
