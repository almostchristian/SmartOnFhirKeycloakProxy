using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using SmartClaimsProvider.Models;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SmartClaimsProvider;

public class AddSmartClaimsFunction(ILogger<AddSmartClaimsFunction> logger, IMemoryCache memoryCache)
{
    [Function("AddSmartClaims")]
    public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
    {
        string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        logger.LogInformation("Processing body {RequestBody}", requestBody);
        TokenIssuanceStartRequest data = JsonSerializer.Deserialize(requestBody, AppJsonSerializerContext.Default.TokenIssuanceStartRequest)!;

        if (data.data.authenticationContext.clientServicePrincipal?.id is string clientId && memoryCache.TryGetValue(clientId, out var value) && value is SmartParameters smartParams)
        {
            logger.LogInformation("Found SmartParameters {Values}", smartParams);
        }
        else
        {
            smartParams = new("example-patient-id", "enc1", "1");
        }

        // Read the correlation ID from the Microsoft Entra request    
        var correlationId = data.data.authenticationContext.correlationId;

        // Claims to return to Microsoft Entra
        ResponseContent r = new ResponseContent();
        r.data.Actions[0].Claims.CorrelationId = correlationId.ToString("N");
        r.data.Actions[0].Claims.Patient = smartParams.Patient;
        r.data.Actions[0].Claims.Tenant = smartParams.Tenant;
        r.data.Actions[0].Claims.Encounter = smartParams.Encounter;

        logger.LogInformation("Returned body {ResponseBody}", JsonSerializer.Serialize(r, AppJsonSerializerContext.Default.ResponseContent));
        return new OkObjectResult(r);
    }

    [Function("SaveSmartClaims")]
    public IActionResult SaveClaims([HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequest req)
    {
        string? clientId = req.Query["client_id"];
        string? patient = req.Query["patient"];
        string? encounter = req.Query["encounter"];
        string? tenant = req.Query["tenant"];

        memoryCache.Set(clientId!, new SmartParameters(patient, encounter, tenant));

        logger.LogInformation("Saving SMART claims {Patient} {Encounter} {Tenant}", patient, encounter, tenant);
        return new OkResult();
    }
}

public class ResponseContent
{
    [JsonPropertyName("data")]
    public ResponseData data { get; set; }
    public ResponseContent()
    {
        data = new ResponseData();
    }
}

public class ResponseData
{
    [JsonPropertyName("@odata.type")]
    public string odatatype { get; set; }

    public List<Action> Actions { get; set; }
    public ResponseData()
    {
        odatatype = "microsoft.graph.onTokenIssuanceStartResponseData";
        Actions = [new()];
    }
}
public class Action
{
    [JsonPropertyName("@odata.type")]
    public string odatatype { get; set; }
    public Claims Claims { get; set; }
    public Action()
    {
        odatatype = "microsoft.graph.tokenIssuanceStart.provideClaimsForToken";
        Claims = new Claims();
    }
}
public class Claims
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CorrelationId { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Patient { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Encounter { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Tenant { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(TokenIssuanceStartRequest))]
[JsonSerializable(typeof(ResponseContent), GenerationMode = JsonSourceGenerationMode.Metadata)]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}

internal record SmartParameters(string? Patient, string? Encounter, string? Tenant);
