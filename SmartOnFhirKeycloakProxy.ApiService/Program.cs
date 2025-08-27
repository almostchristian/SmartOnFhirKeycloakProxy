using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Interfaces;

var builder = WebApplication.CreateBuilder(args);

string keyCloakProxyUrl = builder.Configuration.GetValue<string>("Services:smartonfhirproxy:http:0");
var openApiSecurity = new Microsoft.OpenApi.Models.OpenApiSecurityScheme
{
    Name = "oidc",
    Reference = new Microsoft.OpenApi.Models.OpenApiReference { Id = "oidc", Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme },
    Type = Microsoft.OpenApi.Models.SecuritySchemeType.OAuth2,
    Extensions = new Dictionary<string, IOpenApiExtension>
    {
        { "x-client-id", new Microsoft.OpenApi.Any.OpenApiString("ehr-app") },
        { "x-default-scopes", new Microsoft.OpenApi.Any.OpenApiArray(){ new Microsoft.OpenApi.Any.OpenApiString("user/Appointment.cruds") } }
    },
    Flows = new Microsoft.OpenApi.Models.OpenApiOAuthFlows
    {
        AuthorizationCode = new Microsoft.OpenApi.Models.OpenApiOAuthFlow
        {
            AuthorizationUrl = new Uri($"{keyCloakProxyUrl}/auth"),
            TokenUrl = new Uri($"{keyCloakProxyUrl}/token"),
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
            TokenUrl = new Uri($"{keyCloakProxyUrl}/token"),
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
    .AddKeycloakJwtBearer("keycloak", "fhir", o =>
    {
        o.RequireHttpsMetadata = false;
        o.TokenValidationParameters ??= new Microsoft.IdentityModel.Tokens.TokenValidationParameters();
        o.TokenValidationParameters.ValidAudiences = [ "smart-app", "ehr-app" ];
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
