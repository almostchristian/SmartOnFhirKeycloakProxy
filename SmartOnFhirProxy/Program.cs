using System.Collections.Frozen;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Elders.RedLock;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using ZiggyCreatures.Caching.Fusion;

var builder = WebApplication.CreateSlimBuilder(args);
var realm = builder.Configuration["KEYCLOAK_REALM"] ?? "fhir";
var keycloakUrl = builder.Configuration["KEYCLOAK_URL"] ?? "http://localhost:8080";

var receiveEndpoint = "http://localhost:5032/receive";

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
    client.BaseAddress = new Uri(keycloakUrl);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
});

builder.Services.AddRedLock<RedlockConfigureOptions>();
var app = builder.Build();

app.MapDefaultEndpoints();
app.UseCors();

app.MapGet("/states", ([FromServices] IFusionCache cache) =>
{
    return Results.Ok();
});

// create proxy for OIDC authorization endpoint that redirects to http://localhost:8080/realms/fhir/protocol/openid-connect/auth
app.MapGet("/auth", async (HttpContext context, [FromServices] IFusionCache cache, string client_id, string scope, string redirect_uri, string state, string? launch = null, string? aud = null) =>
{
    var launchVals = launch != null ? Convert.FromBase64String(WebUtility.UrlDecode(launch)) : [];
    var decryptedLaunch = launchVals.Length > 0 ? JsonSerializer.Deserialize(launchVals, AppJsonSerializerContext.Default.DictionaryStringString) : null;

    var newState = Guid.NewGuid().ToString();
    await cache.SetAsync(newState, new AppLaunchRequest(redirect_uri, client_id, state, decryptedLaunch), new() { Duration = TimeSpan.FromSeconds(120) });

    var redirectUrl = receiveEndpoint;

    var query = context.Request.Query.ToDictionary(x => x.Key, x => x.Value);
    query["redirect_uri"] = redirectUrl;
    query["state"] = newState;

    if (launch != null && decryptedLaunch?.Count != 0)
    {
        Debug.WriteLine($"Launch parameter: {launch}");
    }
    else if (scope.Split(' ').Any(x => x == "launch" || x.StartsWith("launch/")))
    {
        //query["error"] = "Launch context is required when scope includes launch";
        //return Results.BadRequest(new ErrorResponse { error = "invalid_launch_parameter", error_description = "Launch context is required when scope includes launch" });
        return Results.Redirect($"{redirect_uri}?state={state}&error=invalid_launch_parameter&error_description=Launch%20parameter%20is%20required%20when%20scope%20includes%20launch");
    }

    query.Remove("launch");
    if (aud == null)
    {
        query["aud"] = client_id;
    }

    return Results.Redirect($"{keycloakUrl}/realms/{realm}/protocol/openid-connect/auth?{string.Join('&', query.Select(x => $"{x.Key}={WebUtility.UrlEncode(x.Value)}"))}");
});

app.MapGet("/receive", async (HttpContext context, [FromServices] IFusionCache cache, [FromServices] IHttpClientFactory httpClientFactory, string state, string? session_state = null) =>
{
    var maybeLaunch = await cache.TryGetAsync<AppLaunchRequest>(state);
    if (!maybeLaunch.HasValue)
    {
        return Results.BadRequest("Invalid state parameter.");
    }

    await cache.RemoveAsync(state);
    var launchParams = maybeLaunch.Value;
    if (context.Request.Query.TryGetValue("error", out var errorMsg))
    {
        return Results.BadRequest($"Failed: {errorMsg}");
    }

    var updated = launchParams with
    {
        Code = context.Request.Query["code"],
        SessionState = session_state,
    };

    var code = context.Request.Query["code"].ToString()!;
    var codeExchange = new AppCodeExchangeRequest(launchParams.ClientId, launchParams.LaunchParameters, session_state);

    await cache.SetAsync(code, codeExchange, tags: session_state != null ? [session_state] : []);

    var query = context.Request.Query.ToDictionary(x => x.Key, x => x.Value.ToString());
    query["state"] = launchParams.State;

    return Results.Redirect($"{launchParams.RedirectUri}?{string.Join('&', query.Select(x => $"{x.Key}={WebUtility.UrlEncode(x.Value)}"))}");
});

app.MapPost("/token", async (HttpContext context, [FromServices] IFusionCache cache, [FromServices] IRedisLockManager redlock, [FromServices] IHttpClientFactory httpClientFactory) =>
{
    using var client = httpClientFactory.CreateClient("keycloak");
    var form = context.Request.Form.ToDictionary(x => x.Key, x => x.Value.ToString());

    string grantType = form["grant_type"];
    string? code = null;
    string? updateLock = null;

    try
    {
        if (grantType == "authorization_code" && form.TryGetValue("code", out code))
        {
            var maybeCodeExchange = await cache.TryGetAsync<AppCodeExchangeRequest>(code);
            if (maybeCodeExchange.HasValue)
            {
                await cache.RemoveAsync(code);
                var exchangeRequest = maybeCodeExchange.Value;
                if (exchangeRequest.LaunchParameters?.Count > 0 && exchangeRequest.SessionState != null)
                {
                    using var adminClient = httpClientFactory.CreateClient("keycloak");
                    updateLock = await UpdateUserProfileAttributesAndLock(adminClient, exchangeRequest.ClientId, exchangeRequest.SessionState, realm, exchangeRequest.LaunchParameters, redlock);
                }
            }
            else
            {
                return Results.BadRequest("Invalid code parameter.");
            }

            form["redirect_uri"] = receiveEndpoint;
        }
        else if (grantType == "password" && !form.ContainsKey("aud"))
        {
            form["aud"] = form["client_id"];
        }

        var rewrittenForm = new FormUrlEncodedContent(form);
        var response = await client.PostAsync($"realms/{realm}/protocol/openid-connect/token", rewrittenForm);

        var responseBody = await response.Content.ReadAsStringAsync();
        if (JsonSerializer.Deserialize(responseBody, AppJsonSerializerContext.Default.BearerToken) is BearerToken bear)
        {
            if (grantType == "password" && bear.session_state != null)
            {
                var launchVals = form.Where(static x => App.KnownAttributes.Contains(x.Key))
                    .ToDictionary(x => x.Key, x => x.Value);

                if (launchVals.Count > 0)
                {
                    code = Guid.NewGuid().ToString();
                    updateLock = await UpdateUserProfileAttributesAndLock(client, form["client_id"], bear.session_state, realm, launchVals, redlock);

                    // get a new token
                    var updatedResponse = await client.PostAsync($"realms/{realm}/protocol/openid-connect/token", rewrittenForm);

                    responseBody = await updatedResponse.Content.ReadAsStringAsync();
                }
            }
            else
            {
                await cache.RemoveByTagAsync(bear.session_state!);
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

public record class BearerToken(string access_token, string token_type, int expires_in, string scope, string? refresh_token = null, string? id_token = null, string? session_state = null);

public record class AppCodeExchangeRequest(string ClientId, Dictionary<string, string>? LaunchParameters = null, string? SessionState = null);

public record class AppLaunchRequest(string RedirectUri, string ClientId, string State, Dictionary<string, string>? LaunchParameters = null, string? SessionState = null, string? UserId = null, string? Code = null);

public record class TokenResponse(string access_token, string token_type, int expires_in, string scope, string refresh_token, string id_token);

public record class ClientSessionStatsResponse(string offline, string clientId, string active, string id);

public record class ClientUserSessionResponse(string id, string username, string userId, long start, long lastAccess);

public record class KeycloakUserResponse(string id, long createdTimestamp, string username, bool enabled, bool totp, bool emailVerified, string email, string firstName, string lastName, Dictionary<string, string[]> attributes, Dictionary<string, bool> access, int notBefore);

public record class ErrorResponse(string error, string error_description);

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
