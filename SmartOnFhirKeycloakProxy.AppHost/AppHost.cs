var builder = DistributedApplication.CreateBuilder(args);

var cache = builder.AddRedis("cache");

var keycloak = builder.AddKeycloak("keycloak", 8080, adminPassword: builder.AddParameter("keycloak-password", value: "admin", secret: true))
                      .WithImageTag("latest")
                      //.WithImageTag("25.0")
                      //.WithDataVolume();
                      .WithRealmImport("realms")
                      .WithArgs("--verbose");

var proxy = builder.AddProject<Projects.SmartOnFhirProxy>("smartonfhirproxy")
    .WithEnvironment("ConnectionStrings__keycloak", keycloak.GetEndpoint("http"))
    .WithReference(cache);

var apiService = builder.AddProject<Projects.SmartOnFhirKeycloakProxy_ApiService>("apiservice")
    .WithHttpHealthCheck("/health")
    .WithReference(keycloak)
    .WithReference(proxy);

builder.AddAzureFunctionsProject<Projects.SmartClaimsProvider>("smartclaimsprovider");

builder.Build().Run();
