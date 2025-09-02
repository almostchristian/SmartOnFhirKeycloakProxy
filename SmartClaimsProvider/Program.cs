using Azure.Core.Serialization;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SmartClaimsProvider;
using System.Text.Json;

var builder = FunctionsApplication.CreateBuilder(args);
builder.AddServiceDefaults();

var jso = new JsonSerializerOptions();
jso.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
builder.ConfigureFunctionsWebApplication()
    .Services.Configure<WorkerOptions>(o => o.Serializer = new JsonObjectSerializer(jso));

// Application Insights isn't enabled by default. See https://aka.ms/AAt8mw4.
// builder.Services
//     .AddApplicationInsightsTelemetryWorkerService()
//     .ConfigureFunctionsApplicationInsights();

builder.Build().Run();
