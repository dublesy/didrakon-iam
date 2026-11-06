using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sample;

const string Cookie = CookieAuthenticationDefaults.AuthenticationScheme;
const string Oidc = OpenIdConnectDefaults.AuthenticationScheme;
const string BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

var builder = WebApplication.CreateBuilder(args);
var issuer = (builder.Configuration["IAM_ISSUER"] ?? "http://localhost:8080").TrimEnd('/');
var clientId = builder.Configuration["IAM_CLIENT_ID"] ?? "sample-dotnet";
var clientSecret = builder.Configuration["IAM_CLIENT_SECRET"] ?? "dummy-secret";
var webhookSecret = builder.Configuration["WEBHOOK_SECRET"]
    ?? throw new InvalidOperationException("WEBHOOK_SECRET 가 없습니다");

var users = new LocalUsers();
var sessions = new SessionStore();

builder.Services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = Cookie;
        o.DefaultChallengeScheme = Oidc;
    })
    .AddCookie(o =>
    {
        o.SessionStore = sessions;   // 쿠키에는 세션 키만 담는다
        o.Events.OnRedirectToLogin = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
    })
    .AddOpenIdConnect(o =>
    {
        o.Authority = issuer;                 // {issuer}/.well-known/openid-configuration 을 읽는다
        o.RequireHttpsMetadata = issuer.StartsWith("https://");
        o.ClientId = clientId;
        o.ClientSecret = clientSecret;
        o.ResponseType = "code";
        o.ResponseMode = "query";             // 기본값 form_post 대신 query
        o.UsePkce = true;
        o.SaveTokens = true;                  // 로그아웃 때 id_token_hint 로 쓴다
        o.CallbackPath = "/callback";
        o.Scope.Clear();
        o.Scope.Add("openid");
        o.Scope.Add("profile");
        o.MapInboundClaims = false;           // sub·sid·roles 를 이름 그대로 둔다
        o.GetClaimsFromUserInfoEndpoint = false;
        o.TokenValidationParameters.NameClaimType = "name";
        // http 로컬에서도 state·nonce 쿠키가 남게 (운영은 https 라 기본값으로 둔다)
        o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.CorrelationCookie.SameSite = SameSiteMode.Lax;
        o.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.NonceCookie.SameSite = SameSiteMode.Lax;
        // 이 핸들러는 client_secret_post 만 지원한다. IAM 등록값(client_secret_basic)에 맞춰 헤더로 보낸다
        o.BackchannelHttpHandler = new ClientSecretBasicHandler(clientId, clientSecret);
        o.Events.OnAuthorizationCodeReceived = ctx =>
        {
            ctx.TokenEndpointRequest!.ClientId = null;
            ctx.TokenEndpointRequest.ClientSecret = null;
            return Task.CompletedTask;
        };
        // ID 토큰 검증(서명·iss·aud·exp·nonce)이 끝난 뒤: 계정 연결
        o.Events.OnTokenValidated = ctx =>
        {
            var p = ctx.Principal!;
            var user = users.Link(p.FindFirstValue("sub")!, p.FindFirstValue("emp_no"), p.FindFirstValue("name"));
            if (!user.Enabled)
            {
                ctx.Fail("disabled local account");
                return Task.CompletedTask;
            }
            ((ClaimsIdentity)p.Identity!).AddClaim(new Claim("local_user_id", user.Id.ToString()));
            return Task.CompletedTask;
        };
        o.Events.OnRemoteFailure = ctx =>
        {
            ctx.HandleResponse();
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return ctx.Response.WriteAsync("login failed");
        };
        // 로그아웃: id_token_hint 만 보낸다 (post_logout_redirect_uri 를 등록하지 않았다)
        o.Events.OnRedirectToIdentityProviderForSignOut = ctx =>
        {
            ctx.ProtocolMessage.PostLogoutRedirectUri = null;
            return Task.CompletedTask;
        };
    });

var app = builder.Build();
app.UseAuthentication();

app.MapGet("/login", () =>
    Results.Challenge(new AuthenticationProperties { RedirectUri = "/me" }, [Oidc]));

// /callback 은 OIDC 핸들러가 처리한다 (CallbackPath). 끝나면 RedirectUri(/me)로 보낸다

app.MapGet("/me", (ClaimsPrincipal user) =>
    user.Identity?.IsAuthenticated != true
        ? Results.Unauthorized()
        : Results.Json(new
        {
            sub = user.FindFirstValue("sub"),
            name = user.FindFirstValue("name"),
            empNo = user.FindFirstValue("emp_no"),
            roles = user.FindAll("roles").Select(c => c.Value),
            localUserId = long.Parse(user.FindFirstValue("local_user_id")!),
            sid = user.FindFirstValue("sid"),
        }));

// 앱 세션을 지우고 IAM /connect/logout?id_token_hint=... 로
app.MapGet("/logout", () => Results.SignOut(new AuthenticationProperties(), [Cookie, Oidc]));

// OIDC Back-Channel Logout 1.0
app.MapPost("/backchannel-logout", async (HttpRequest req, IOptionsMonitor<OpenIdConnectOptions> oidcOptions) =>
{
    if (!req.HasFormContentType) return Results.BadRequest();
    var token = (await req.ReadFormAsync())["logout_token"].ToString();
    var options = oidcOptions.Get(Oidc);
    var config = await options.ConfigurationManager!.GetConfigurationAsync(req.HttpContext.RequestAborted);

    var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
    {
        ValidIssuer = issuer,
        ValidAudience = clientId,
        IssuerSigningKeys = config.SigningKeys,   // JWKS
        ValidTypes = ["logout+jwt"],              // 헤더 typ
        RequireExpirationTime = true,
    });
    if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt) return Results.BadRequest();

    var hasEvent = jwt.TryGetPayloadValue<JsonElement>("events", out var events)
                   && events.ValueKind == JsonValueKind.Object
                   && events.TryGetProperty(BackChannelLogoutEvent, out _);
    var hasIat = jwt.TryGetPayloadValue<long>("iat", out _);
    var hasNonce = jwt.TryGetClaim("nonce", out _);
    var sid = jwt.TryGetClaim("sid", out var sidClaim) ? sidClaim.Value : null;
    var sub = string.IsNullOrEmpty(jwt.Subject) ? null : jwt.Subject;
    if (!hasEvent || !hasIat || hasNonce || (sub == null && sid == null)) return Results.BadRequest();

    // sid 가 있으면 그 로그인 세션만, 없으면 sub 의 세션을 모두 끝낸다
    var ended = sessions.End(sub, sid);
    req.HttpContext.Response.Headers.CacheControl = "no-store";
    return Results.Ok(new { ended });
});

// IAM 웹훅: 서명 → 시각 → 중복 순서로 거른다
var processed = new System.Collections.Concurrent.ConcurrentDictionary<string, bool>();  // 실제로는 DB 테이블
var webhookKey = Encoding.UTF8.GetBytes(webhookSecret);

app.MapPost("/webhooks/iam", async (HttpRequest req) =>
{
    // 본문은 받은 바이트 그대로 쓴다. 객체로 읽어 다시 직렬화하면 서명이 맞지 않는다
    using var buffer = new MemoryStream();
    await req.Body.CopyToAsync(buffer);
    var body = buffer.ToArray();
    var timestamp = req.Headers["X-Didrakon-Timestamp"].ToString();
    var signature = req.Headers["X-Didrakon-Signature"].ToString();
    var delivery = req.Headers["X-Didrakon-Delivery"].ToString();

    var signed = Encoding.UTF8.GetBytes(timestamp + ".").Concat(body).ToArray();
    var expected = "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(webhookKey, signed));
    if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(signature)))
        return Results.Json(new { error = "bad signature" }, statusCode: 401);

    if (!long.TryParse(timestamp, out var ts) || Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - ts) > 300)
        return Results.Json(new { error = "stale timestamp" }, statusCode: 401);

    if (!processed.TryAdd(delivery, true)) return Results.Ok(new { duplicate = true });

    using var doc = JsonDocument.Parse(body);
    var root = doc.RootElement;
    if (root.GetProperty("type").GetString() == "user.status_changed"
        && root.GetProperty("data").GetProperty("status").GetString() == "RETIRED")
    {
        var sub = root.GetProperty("data").GetProperty("subjectId").ToString();
        users.Disable(sub);        // 계정 끄기 (권한 회수는 시스템마다)
        sessions.End(sub, null);   // 그 사람의 세션 모두 종료
    }
    return Results.Ok(new { ok = true });
});

app.Run();

/// <summary>토큰 요청(POST)에 client_secret_basic 헤더를 붙인다. discovery·JWKS(GET)에는 붙이지 않는다</summary>
sealed class ClientSecretBasicHandler(string clientId, string clientSecret) : DelegatingHandler(new HttpClientHandler())
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.Method == HttpMethod.Post)
        {
            // RFC 6749 2.3.1: 각각 form-urlencode 한 뒤 Basic 으로
            var raw = $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret)}";
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)));
        }
        return base.SendAsync(request, ct);
    }
}
