using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// 忽略 SSL 憑證錯誤（開發環境）
var handler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
};

var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://localhost:7138") };

Console.WriteLine("=== SSO.Auth Server 測試工具 ===");
Console.WriteLine();

await TestClientCredentialsAsync();
Console.WriteLine();
await TestAuthorizationCodePkceAsync();

static async Task TestClientCredentialsAsync()
{
    Console.WriteLine("╔══════════════════════════════════════════╗");
    Console.WriteLine("║  測試 1：Client Credentials（.NET Web API） ║");
    Console.WriteLine("╚══════════════════════════════════════════╝");
    Console.WriteLine("情境：Web API 以後台服務身份向 AuthServer 要求 Token，");
    Console.WriteLine("      不需使用者介入。");
    Console.WriteLine();

    var parameters = new Dictionary<string, string>
    {
        ["grant_type"] = "client_credentials",
        ["client_id"] = "dotnet-webapi",
        ["client_secret"] = "s8At8YiVDxeVnuE+DWsAMqNCzkTX+DEinxKjWnpBOXw=",
        ["scope"] = "api"
    };

    var httpClient = new HttpClient(new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    })
    { BaseAddress = new Uri("https://localhost:7138") };

    // Step 1: 取得 Token
    Console.Write("❶ 向 /connect/token 請求 Access Token...");
    var response = await httpClient.PostAsync("/connect/token",
        new FormUrlEncodedContent(parameters));
    var json = await response.Content.ReadAsStringAsync();

    if (!response.IsSuccessStatusCode)
    {
        Console.WriteLine($" ❌ 失敗：{response.StatusCode}");
        Console.WriteLine(JsonSerializer.Serialize(
            JsonSerializer.Deserialize<JsonElement>(json),
            new JsonSerializerOptions { WriteIndented = true }));
        return;
    }
    Console.WriteLine(" ✅ 成功！");
    Console.WriteLine();

    var tokenResponse = JsonSerializer.Deserialize<JsonElement>(json);
    var accessToken = tokenResponse.GetProperty("access_token").GetString()!;
    Console.WriteLine($"   Access Token (前50字元): {accessToken[..Math.Min(50, accessToken.Length)]}...");
    Console.WriteLine($"   Token 類型: {tokenResponse.GetProperty("token_type")}");
    Console.WriteLine($"   有效期限: {tokenResponse.GetProperty("expires_in")} 秒");
    Console.WriteLine();

    // Step 2: 用 Token 呼叫 UserInfo
    Console.Write("❷ 用 Access Token 呼叫 /connect/userinfo...");
    httpClient.DefaultRequestHeaders.Authorization =
        new AuthenticationHeaderValue("Bearer", accessToken);
    var userInfoResponse = await httpClient.GetAsync("/connect/userinfo");
    var userInfoJson = await userInfoResponse.Content.ReadAsStringAsync();

    if (!userInfoResponse.IsSuccessStatusCode)
    {
        Console.WriteLine($" ❌ 失敗：{userInfoResponse.StatusCode}");
        Console.WriteLine(userInfoJson);
        return;
    }
    Console.WriteLine(" ✅ 成功！");
    Console.WriteLine($"   回傳內容: {JsonSerializer.Serialize(
        JsonSerializer.Deserialize<JsonElement>(userInfoJson),
        new JsonSerializerOptions { WriteIndented = true })}");
    Console.WriteLine();

    Console.WriteLine("✅ Client Credentials 流程測試完成！");
    Console.WriteLine("   實際 Web API 用法：在每個 API 請求的 Header 加上");
    Console.WriteLine("   Authorization: Bearer {access_token}");
    Console.WriteLine("   然後在 Web API 中驗證此 Token 即可。");
}

static async Task TestAuthorizationCodePkceAsync()
{
    Console.WriteLine("╔══════════════════════════════════════════════╗");
    Console.WriteLine("║  測試 2：授權碼流程 + PKCE（Blazor WASM）     ║");
    Console.WriteLine("╚══════════════════════════════════════════════╝");
    Console.WriteLine("情境：使用者透過瀏覽器登入，Blazor WASM 取得 Token 後");
    Console.WriteLine("      攜帶 Token 呼叫 Web API。");
    Console.WriteLine();

    Console.WriteLine("由於 PKCE 需要瀏覽器交互，請按以下步驟手動測試：");
    Console.WriteLine();
    Console.WriteLine("步驟 ── 瀏覽器操作 ──");
    Console.WriteLine();
    Console.WriteLine("  Step 1: 在瀏覽器開啟以下網址（模擬 Blazor 啟動授權）：");
    Console.WriteLine();
    Console.WriteLine($"    https://localhost:7138/connect/authorize");
    Console.WriteLine($"    ?client_id=blazor-wasm");
    Console.WriteLine($"    &redirect_uri=http://localhost:5000/authentication/login-callback");
    Console.WriteLine($"    &response_type=code");
    Console.WriteLine($"    &scope=openid%20profile%20api");
    Console.WriteLine($"    &state={Guid.NewGuid():N}");
    Console.WriteLine($"    &code_challenge=TEST_CHALLENGE");
    Console.WriteLine($"    &code_challenge_method=S256");
    Console.WriteLine();
    Console.WriteLine("  Step 2: 瀏覽器會跳轉到 Identity 登入頁面");
    Console.WriteLine("          帳號: admin@sso.local");
    Console.WriteLine("          密碼: Admin123!");
    Console.WriteLine();
    Console.WriteLine("  Step 3: 登入成功後，瀏覽器會重新導向回 Blazor 的回呼網址");
    Console.WriteLine("          (redirect_uri)，URL 中會包含授權碼 (code=xxx)");
    Console.WriteLine();
    Console.WriteLine("  Step 4: Blazor WASM 會用此授權碼向 Token 端點交換 Token：");
    Console.WriteLine();
    Console.WriteLine("    POST https://localhost:7138/connect/token");
    Console.WriteLine("    Content-Type: application/x-www-form-urlencoded");
    Console.WriteLine();
    Console.WriteLine("    grant_type=authorization_code");
    Console.WriteLine("    &client_id=blazor-wasm");
    Console.WriteLine("    &redirect_uri=http://localhost:5000/authentication/login-callback");
    Console.WriteLine("    &code=【上一步取得的授權碼】");
    Console.WriteLine("    &code_verifier=【PKCE code_verifier】");
    Console.WriteLine();
    Console.WriteLine("  Step 5: 成功後會取得 access_token + refresh_token");
    Console.WriteLine("          Blazor 將 access_token 存在記憶體中。");
    Console.WriteLine();
    Console.WriteLine("  Step 6: Blazor 呼叫 Web API 時帶上 Token：");
    Console.WriteLine();
    Console.WriteLine("    GET https://localhost:5001/api/weatherforecast");
    Console.WriteLine("    Authorization: Bearer {access_token}");
    Console.WriteLine();
    Console.WriteLine("  Step 7: Token 過期後，Blazor 用 refresh_token 換新 Token：");
    Console.WriteLine();
    Console.WriteLine("    POST https://localhost:7138/connect/token");
    Console.WriteLine("    Content-Type: application/x-www-form-urlencoded");
    Console.WriteLine();
    Console.WriteLine("    grant_type=refresh_token");
    Console.WriteLine("    &client_id=blazor-wasm");
    Console.WriteLine("    &refresh_token=【refresh_token】");
    Console.WriteLine();
    Console.WriteLine("  Step 8: 登出觸發 SLO：");
    Console.WriteLine();
    Console.WriteLine("    GET https://localhost:7138/connect/endsession");
    Console.WriteLine("    ?post_logout_redirect_uri=http://localhost:5000");
    Console.WriteLine();
    Console.WriteLine("    此動作會清除 Cookie 並撤銷所有 Refresh Token。");
}
