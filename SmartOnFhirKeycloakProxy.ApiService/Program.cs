using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Interfaces;

var builder = WebApplication.CreateBuilder(args);

string smartProxyUrl = builder.Configuration.GetValue<string>("Services:smartonfhirproxy:http:0");
string defaultClientId = builder.Configuration.GetValue<string>("DefaultClientId") ?? "ehr-app";
string audience = builder.Configuration.GetValue<string>("Audience") ?? builder.Configuration.GetValue<string>("DefaultClientId") ?? "http://fhirnexusapp";
var openApiSecurity = new Microsoft.OpenApi.Models.OpenApiSecurityScheme
{
    Name = "oidc",
    Reference = new Microsoft.OpenApi.Models.OpenApiReference { Id = "oidc", Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme },
    Type = Microsoft.OpenApi.Models.SecuritySchemeType.OAuth2,
    Extensions = new Dictionary<string, IOpenApiExtension>
    {
        { "x-client-id", new Microsoft.OpenApi.Any.OpenApiString(defaultClientId) },
        { "x-default-scopes", new Microsoft.OpenApi.Any.OpenApiArray(){ new Microsoft.OpenApi.Any.OpenApiString("patient/Appointment.crus"), new Microsoft.OpenApi.Any.OpenApiString("launch/patient") } }
    },
    Flows = new Microsoft.OpenApi.Models.OpenApiOAuthFlows
    {
        AuthorizationCode = new Microsoft.OpenApi.Models.OpenApiOAuthFlow
        {
            AuthorizationUrl = new Uri($"{smartProxyUrl}/auth"),
            TokenUrl = new Uri($"{smartProxyUrl}/token"),
            Scopes = new Dictionary<string, string>
            {
                { "patient/Appointment.crus", "Create/Read Appointment for Patient" },
                { "user/Appointment.cruds", "Create/Read/Update/Delete/Search Appointment" },
                { "launch/patient", "Adds patient claim" },
                { "launch/encounter", "Adds encounter claim" },
                { "launch", "EHR launch" },
                { "profile", "Adds firstName and lastName claims" },
            }
        },
        Password = new Microsoft.OpenApi.Models.OpenApiOAuthFlow
        {
            TokenUrl = new Uri($"{smartProxyUrl}/token"),
            Scopes = new Dictionary<string, string>
            {
                { "patient/Appointment.crus", "Create/Read Appointment for Patient" },
                { "user/Appointment.cruds", "Create/Read/Update/Delete/Search Appointment" },
                { "launch/patient", "Adds patient claim" },
                { "launch/encounter", "Adds encounter claim" },
                { "launch", "EHR launch" },
                { "profile", "Adds firstName and lastName claims" },
            }
        }
    }
};
builder.AddServiceDefaults();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o => o.SwaggerGeneratorOptions.SecuritySchemes["oidc"] = openApiSecurity);
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, "keycloak", o =>
    {
        o.RequireHttpsMetadata = false;
        o.TokenHandlers.Clear();
        o.TokenHandlers.Add(new ExpiryValidatingJsonWebTokenHandler());
        o.MetadataAddress = $"{smartProxyUrl}/.well-known/openid-configuration";
        o.Audience = audience;
        o.Events ??= new();
        o.Events.OnAuthenticationFailed += c =>
        {
            var logger = c.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("KeycloakJwtBearer");
            logger.LogError(c.Exception, "Authentication failed");
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();

// Add services to the container.
builder.Services.AddProblemDetails();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseExceptionHandler();
app.UseStaticFiles();
app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/user", (HttpContext context) =>
{
    var claims = context.User.Claims
        .Select(c => new { c.Type, c.Value })
        .ToArray();
    return claims;
})
.WithName("GetUser")
.WithOpenApi(o =>
{
    o.Security.Add(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement { { openApiSecurity, [] } });
    return o;
});


app.MapDefaultEndpoints();

app.Run();

internal class ExpiryValidatingJsonWebTokenHandler : JsonWebTokenHandler
{
    public override async Task<TokenValidationResult> ValidateTokenAsync(SecurityToken token, TokenValidationParameters validationParameters)
    {
        var result = await base.ValidateTokenAsync(token, validationParameters);

        if (result.IsValid && result.Claims.TryGetValue("sid", out var sid) && sid is string sessionId)
        {
            // check if valid
        }

        return result;
    }
}
