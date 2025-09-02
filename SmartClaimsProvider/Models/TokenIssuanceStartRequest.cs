using System.Text.Json.Serialization;
 
namespace SmartClaimsProvider.Models;

public class TokenIssuanceStartRequest
{
    public string type { get; set; }
    public string source { get; set; }
    public Data data { get; set; }
}

public class Data
{
    [JsonPropertyName("@odata.type")]
    public string odatatype { get; set; }
    public string tenantId { get; set; }
    public Guid authenticationEventListenerId { get; set; }
    public Guid customAuthenticationExtensionId { get; set; }
    public AuthenticationContext authenticationContext { get; set; }
}

public class AuthenticationContext
{
    public Guid correlationId { get; set; }
    public Client client { get; set; }
    public string protocol { get; set; }
    public ClientServicePrincipal clientServicePrincipal { get; set; }
    public ResourceServiceprincipal resourceServicePrincipal { get; set; }
    public User? user { get; set; }
}

public class Client
{
    public string ip { get; set; }
    public string locale { get; set; }
    public string market { get; set; }
}

public class ClientServicePrincipal
{
    public string id { get; set; }
    public string appId { get; set; }
    public string appDisplayName { get; set; }
    public string? displayName { get; set; }
}

public class ResourceServiceprincipal
{
    public string id { get; set; }
    public string appId { get; set; }
    public string? appDisplayName { get; set; }
    public string? displayName { get; set; }
}

public class User
{
    public string? companyName { get; set; }
    public DateTimeOffset createdDateTime { get; set; }
    public string? displayName { get; set; }
    public string? givenName { get; set; }
    public string id { get; set; }
    public string? mail { get; set; }
    public string? onPremisesSamAccountName { get; set; }
    public string? onPremisesSecurityIdentifier { get; set; }
    public string? onPremisesUserPrincipalName { get; set; }
    public string? preferredLanguage { get; set; }
    public string? surname { get; set; }
    public string userPrincipalName { get; set; }
    public string userType { get; set; }
}
