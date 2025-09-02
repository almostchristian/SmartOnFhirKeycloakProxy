using Elders.RedLock;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using ZiggyCreatures.Caching.Fusion;

var builder = WebApplication.CreateSlimBuilder(args);
var keycloakUrl = builder.Configuration.GetConnectionString("keycloak");
var azureConfig = builder.Configuration.GetSection("Azure").Get<AzureConfig>();
var realm = builder.Configuration.GetValue<string>("KeycloakRealm") ?? "fhir";
bool rewriteJwt = builder.Configuration.GetValue<bool>("IssueRewrittenJwtTokens");
string[] copiedJwtClaims = ["aud", "iss", "exp", "iat", "azp", "email", "name", "sid", "oid"];

builder.AddServiceDefaults();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

// configure CORS to allow all origins, headers, and methods
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod()));

builder.Services.AddStackExchangeRedisCache(o => o.Configuration = builder.Configuration.GetConnectionString("cache"));
builder.Services.AddFusionCache()
    .WithStackExchangeRedisBackplane()
    .WithSerializer(sp =>
    {
        var options = new JsonSerializerOptions();
        options.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
        return new ZiggyCreatures.Caching.Fusion.Serialization.SystemTextJson.FusionCacheSystemTextJsonSerializer(options);
    });

builder.Services.AddHttpClient("keycloak", client =>
{
    client.DefaultRequestHeaders.Add("Accept", "application/json");
});
if (rewriteJwt)
{
    builder.Services.AddSingleton<JsonWebTokenHandler>();
}

builder.Services.AddRedLock<RedlockConfigureOptions>();
var app = builder.Build();

app.MapDefaultEndpoints();
app.UseCors();

SigningCredentials? signingCredentials = null;

if (rewriteJwt)
{
    // create jwks and expose as endpoint
    var rsa = RSA.Create(2048);
    var rsaSecurityKey = new RsaSecurityKey(rsa)
    {
        KeyId = Guid.NewGuid().ToString()
    };

    signingCredentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256)
    {
        CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = true }
    };

    // Build JWKS
    var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaSecurityKey);
    var jwks = new JsonWebKeySet([jwk]);

    // Expose JWKS endpoint
    app.MapGet("/oidc/jwks.json", () =>
    {
        return Results.Json(jwks, AppJsonSerializerContext.Default.JsonWebKeySet);
    });

    app.MapGet("/.well-known/openid-configuration", () =>
    {
        var rootPath = app.Configuration.GetValue<string>("BASE_PATH") ?? app.Urls.First();
        var wellKnown = new OidcWellKnownEndpoint(
            token_endpoint: $"{rootPath}/token",
            jwks_uri: $"{rootPath}/oidc/jwks.json",
            authorization_endpoint: $"{rootPath}/auth",
            issuer: rootPath
        );
        return Results.Json(wellKnown, AppJsonSerializerContext.Default.OidcWellKnownEndpoint);
    });
}
else
{
    if (azureConfig == null)
    {
        app.MapGet("/.well-known/openid-configuration", () =>
        {
            return Results.Redirect($"{keycloakUrl}/realms/{realm}/.well-known/openid-configuration");
        });
    }
    else
    {
        app.MapGet("/.well-known/openid-configuration", () =>
        {
            return Results.Redirect($"https://login.microsoftonline.com/{azureConfig.TenantId}/v2.0/.well-known/openid-configuration");
        });
    }
}

app.MapGet("/states", ([FromServices] IFusionCache cache) =>
{
    return Results.Ok();
});

// create proxy for OIDC authorization endpoint that redirects to http://localhost:8080/realms/fhir/protocol/openid-connect/auth
app.MapGet("/auth", async (HttpContext context, [FromServices] IFusionCache cache, string client_id, string scope, string redirect_uri, string state, string? launch = null, string? aud = null) =>
{
    var launchVals = launch != null ? Convert.FromBase64String(WebUtility.UrlDecode(launch)) : [];
    var decryptedLaunch = launchVals.Length > 0 ? JsonSerializer.Deserialize(launchVals, AppJsonSerializerContext.Default.DictionaryStringString) : null;

    var query = context.Request.Query.ToDictionary(x => x.Key, x => x.Value);

    if (launch != null && decryptedLaunch?.Count != 0)
    {
        Debug.WriteLine($"Launch parameter: {launch}");
    }
    else if (scope.Split(' ').Any(x => x == "launch" || x.StartsWith("launch/")))
    {
        return Results.Redirect($"{redirect_uri}?state={state}&error=invalid_launch_parameter&error_description=Launch%20parameter%20is%20required%20when%20scope%20includes%20launch");
    }

    if (azureConfig?.ScopeFormat is string azureScopeFormat)
    {
        var newScope = string.Join(' ', scope.Split(' ').Select(scope => scope.Contains('/') ? string.Format(azureScopeFormat, scope.Replace('/', '|')) : scope));
        query["scope"] = newScope;
    }

    if (query.TryGetValue("code_challenge", out var codeChallengeVal) && codeChallengeVal.ToString() is string codeChallenge)
    {
        if (codeChallenge.EndsWith('=') || codeChallenge.Contains('/') || codeChallenge.Contains('+'))
        {
            // '=' should be trimmed and '+' and '/' should be replaced to be URL safe
            codeChallenge = codeChallenge.TrimEnd('=').Replace('+', '-').Replace('/', '_');
            query["code_challenge"] = codeChallenge;
        }
    }
    else
    {
        return Results.Redirect($"{redirect_uri}?state={state}&error=missing_pkce_challenge&error_description=PKCE%20%20challenge%20parameter%20is%20required");
    }

    await cache.SetAsync(codeChallenge, new AppLaunchRequest(redirect_uri, client_id, state, decryptedLaunch), new() { Duration = TimeSpan.FromSeconds(120) });

    query.Remove("launch");
    if (aud == null)
    {
        query["aud"] = client_id;
    }

    return Results.Redirect($"{GenerateAuthEndpoint()}?{string.Join('&', query.Select(x => x.Key == "code_challenge" ? $"{x.Key}={x.Value}" : $"{x.Key}={WebUtility.UrlEncode(x.Value)}"))}");
});

app.MapPost("/token", async (HttpContext context, [FromServices] IFusionCache cache, [FromServices] IRedisLockManager redlock, [FromServices] IHttpClientFactory httpClientFactory, [FromServices]JsonWebTokenHandler? handler = null) =>
{
    using var client = httpClientFactory.CreateClient("keycloak");
    var form = context.Request.Form.ToDictionary(x => x.Key, x => x.Value.ToString());

    string grantType = form["grant_type"];
    //string? code = null;
    string? updateLock = null;
    Dictionary<string, string>? launchValues = null;

    try
    {
        if (grantType == "authorization_code" && form.TryGetValue("code_verifier", out var codeVerifier))
        {
            var challenge = Convert.ToBase64String(SHA256.HashData(System.Text.ASCIIEncoding.ASCII.GetBytes(codeVerifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var maybeCodeExchange = await cache.TryGetAsync<AppLaunchRequest>(challenge);
            if (maybeCodeExchange.HasValue)
            {
                await cache.RemoveAsync(challenge);
                var exchangeRequest = maybeCodeExchange.Value;
                launchValues = exchangeRequest.LaunchParameters;
                if (!rewriteJwt && exchangeRequest.LaunchParameters?.Count > 0 && (exchangeRequest.SessionState != null || context.Request.Form.ContainsKey("session_state")) && azureConfig == null)
                {
                    using var adminClient = httpClientFactory.CreateClient("keycloak");
                    adminClient.BaseAddress = new Uri(keycloakUrl);
                    updateLock = await UpdateUserProfileAttributesAndLock(adminClient, exchangeRequest.ClientId, exchangeRequest.SessionState ?? context.Request.Form["session_state"]!, realm, exchangeRequest.LaunchParameters, redlock);
                }
                else if (azureConfig?.TenantSecret is string azureTenantSecret)
                {
                    form["client_secret"] = azureTenantSecret;
                }
            }
            else
            {
                return Results.BadRequest("Invalid code_verifier parameter.");
            }
        }
        else if (grantType == "password" && !form.ContainsKey("aud"))
        {
            form["aud"] = form["client_id"];
        }
        else
        {
            return Results.BadRequest("Invalid grant.");
        }

        var rewrittenForm = new FormUrlEncodedContent(form);
        var response = await client.PostAsync(GenerateTokenEndpoint(), rewrittenForm);

        var responseBody = await response.Content.ReadAsStringAsync();
        if (JsonSerializer.Deserialize(responseBody, AppJsonSerializerContext.Default.BearerToken) is BearerToken bear)
        {
            if (grantType == "password" && bear.session_state != null)
            {
                var launchVals = form.Where(static x => App.KnownAttributes.Contains(x.Key))
                    .ToDictionary(x => x.Key, x => x.Value);

                if (launchVals.Count > 0 && azureConfig == null)
                {
                    var code = Guid.NewGuid().ToString();
                    updateLock = await UpdateUserProfileAttributesAndLock(client, form["client_id"], bear.session_state, realm, launchVals, redlock);

                    // get a new token
                    var updatedResponse = await client.PostAsync(GenerateTokenEndpoint(), rewrittenForm);

                    responseBody = await updatedResponse.Content.ReadAsStringAsync();
                }
            }
            else if (bear.session_state is not null)
            {
                await cache.RemoveByTagAsync(bear.session_state);
            }

            if (rewriteJwt && signingCredentials != null && handler != null)
            {
                // decore bearer_token
                var bearer = handler.ReadJsonWebToken(bear.access_token);

                // create new bearer_token and sign with jwt

                var newClaims = bearer.Claims.Where(x => copiedJwtClaims.Contains(x.Type)).ToDictionary(x => x.Type, x => (object)x.Value);
                var scopes = bearer.Claims.FirstOrDefault(x => x.Type == "scp")?.Value.Split(' ').Select(x => x.Replace('|', '/')).ToArray() ?? [];
                if (scopes.Length > 0)
                {
                    newClaims["scope"] = string.Join(' ', scopes);
                }

                if (launchValues != null)
                {
                    foreach (var (k, v) in launchValues)
                    {
                        newClaims[k] = v;
                    }
                }

                var newToken = handler.CreateToken(new SecurityTokenDescriptor
                {
                    Issuer = app.Urls.First(),
                    Audience = bearer.Audiences.First(),
                    Claims = newClaims,
                    Expires = bearer.ValidTo,
                    IncludeKeyIdInHeader = true,
                    SigningCredentials = signingCredentials,
                });
                var updatedBearer = bear with { access_token = newToken };
                responseBody = JsonSerializer.Serialize(updatedBearer, AppJsonSerializerContext.Default.BearerToken);
            }
        }

        return Results.Content(responseBody, response.Content.Headers.ContentType!.MediaType);
    }
    finally
    {
        if (updateLock != null)
        {
            await redlock.UnlockAsync(updateLock);
        }
    }
});

app.Run();

string GenerateAuthEndpoint()
{
    if (azureConfig == null)
    {
        return $"{keycloakUrl}/realms/{realm}/protocol/openid-connect/auth";
    }
    else
    {
        return $"https://login.microsoftonline.com/{azureConfig.TenantId}/oauth2/v2.0/authorize";
    }
}

string GenerateTokenEndpoint()
{
    if (azureConfig == null)
    {
        return $"{keycloakUrl}/realms/{realm}/protocol/openid-connect/token";
    }
    else
    {
        return $"https://login.microsoftonline.com/{azureConfig.TenantId}/oauth2/v2.0/token";
    }
}

static async Task AuthenticateAdminClient(HttpClient adminClient)
{
    var tokenRequest = await adminClient.PostAsync("realms/master/protocol/openid-connect/token", new StringContent("client_id=admin-cli&grant_type=password&username=admin&password=admin", System.Text.Encoding.ASCII, "application/x-www-form-urlencoded"));

    var tokenResponse = await tokenRequest.Content.ReadFromJsonAsync(AppJsonSerializerContext.Default.TokenResponse);

    // get admin token
    adminClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(tokenResponse.token_type, tokenResponse.access_token);
}

/// based on https://stackoverflow.com/questions/76865285/keycloak-rest-api-is-it-possible-to-update-user-session-data-using-admin-rest
static async Task<string?> UpdateUserProfileAttributesAndLock(HttpClient adminClient, string clientId, string sessionState, string realm, Dictionary<string, string> values, IRedisLockManager redLock)
{
    await AuthenticateAdminClient(adminClient);

    // we get the client session stats to find the client session by clientId
    var clientSessionStatsResponse = await adminClient.GetAsync($"admin/realms/{realm}/client-session-stats");
    ClientSessionStatsResponse? clientSessionStats = await FirstFromJsonAsAsyncEnumerable(clientSessionStatsResponse.Content, AppJsonSerializerContext.Default.ClientSessionStatsResponse, session => session.clientId == clientId);

    if (clientSessionStats != null)
    {
        // we get the session from the user-sessions for the client
        var userSessionsResponse = await adminClient.GetAsync($"admin/realms/{realm}/clients/{clientSessionStats.id}/user-sessions?id={sessionState}");
        ClientUserSessionResponse? userSession = await FirstFromJsonAsAsyncEnumerable(userSessionsResponse.Content, AppJsonSerializerContext.Default.ClientUserSessionResponse, session => session.id == sessionState);

        if (userSession != null)
        {
            if (await redLock.LockAsync(userSession.userId, TimeSpan.FromSeconds(5)))
            {
                try
                {
                    var userResponse = await adminClient.GetAsync($"admin/realms/{realm}/users/{userSession.userId}");
                    var userInfo = await userResponse.Content.ReadFromJsonAsync(AppJsonSerializerContext.Default.KeycloakUserResponse);

                    if (userInfo != null)
                    {
                        // update user with new attributes
                        var attributes = userInfo.attributes ?? [];

                        foreach (var attr in App.KnownAttributes)
                        {
                            if (values.TryGetValue(attr, out var val))
                            {
                                attributes[attr] = [val];
                            }
                            else
                            {
                                attributes.Remove(attr);
                            }
                        }

                        var updated = userInfo with
                        {
                            attributes = attributes,
                        };

                        var updateResponse = await adminClient.PutAsJsonAsync($"admin/realms/{realm}/users/{userInfo.id}", updated, AppJsonSerializerContext.Default.KeycloakUserResponse);

                        Debug.Write(await updateResponse.Content.ReadAsStringAsync());
                        updateResponse.EnsureSuccessStatusCode();
                    }

                    return userSession.userId;
                }
                catch
                {
                    await redLock.UnlockAsync(userSession.userId);
                    throw;
                }
            }
            else
            {
                throw new InvalidOperationException($"Failed to acquire lock for user session {userSession.userId}.");
            }
        }
    }

    return null;

    static async Task<T?> FirstFromJsonAsAsyncEnumerable<T>(HttpContent content, JsonTypeInfo<T> jsonTypeInfo, Func<T, bool> predicate)
        where T : class
    {
        await foreach (var item in content.ReadFromJsonAsAsyncEnumerable(jsonTypeInfo))
        {
            if (item is not null && predicate(item))
            {
                return item;
            }
        }

        return null;
    }
}

public partial class App
{
    public static readonly FrozenSet<string> KnownAttributes = new List<string>(["patient", "encounter", "practitioner", "tenant"]).ToFrozenSet();
}

internal sealed class RedlockConfigureOptions(IConfiguration configuration) : IConfigureOptions<RedLockOptions>
{
    public void Configure(RedLockOptions options)
    {
        configuration.GetSection("RedLock").Bind(options);
        options.ConnectionString = configuration.GetConnectionString("cache");
    }
}

public record class OidcWellKnownEndpoint(string token_endpoint, string jwks_uri, string authorization_endpoint, string issuer);

public record class AzureConfig(string TenantId, string? TenantSecret, string ScopeFormat);

public record class BearerToken(string access_token, string token_type, int expires_in, string scope, string? refresh_token = null, string? id_token = null, string? session_state = null);

public record class AppCodeExchangeRequest(string ClientId, Dictionary<string, string>? LaunchParameters = null, string? SessionState = null);

public record class AppLaunchRequest(string RedirectUri, string ClientId, string State, Dictionary<string, string>? LaunchParameters = null, string? SessionState = null, string? UserId = null, string? Code = null);

public record class TokenResponse(string access_token, string token_type, int expires_in, string scope, string refresh_token, string id_token);

public record class ClientSessionStatsResponse(string offline, string clientId, string active, string id);

public record class ClientUserSessionResponse(string id, string username, string userId, long start, long lastAccess);

public record class KeycloakUserResponse(string id, long createdTimestamp, string username, bool enabled, bool totp, bool emailVerified, string email, string firstName, string lastName, Dictionary<string, string[]> attributes, Dictionary<string, bool> access, int notBefore);

public record class ErrorResponse(string error, string error_description);

public record class JsonWebKeySet(JsonWebKey[] keys);

[JsonSerializable(typeof(OidcWellKnownEndpoint))]
[JsonSerializable(typeof(JsonWebKeySet))]
[JsonSerializable(typeof(AzureConfig))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(RedLockOptions))]
[JsonSerializable(typeof(BearerToken))]
[JsonSerializable(typeof(KeycloakUserResponse))]
[JsonSerializable(typeof(ClientUserSessionResponse))]
[JsonSerializable(typeof(ClientSessionStatsResponse))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof((Dictionary<string, AppLaunchRequest> AppLaunch, Dictionary<string, AppCodeExchangeRequest> CodeExchange)))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}
