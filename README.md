# SMART-on-Fhir Keycloak Proxy

This projects shows a reference implementation for a SMART-on-FHIR authentication server using Keycloak and an OAuth proxy that processes the SMART launch token.


```mermaid
sequenceDiagram
    title FHIR Resource API SMART-on-FHIR with External Identity Provider flow

    autonumber
    actor User

    participant EHR
    participant Smart App
    participant FHIR Resource API
    box SMART-on-FHIR Authz
    participant Smart Proxy
    participant Keycloak
    end
    participant External Identity Provider



    User->EHR:Launch Smart App
    activate EHR

 
    EHR->Smart App:http://smart-app?launch=**<launch_context>**& iss=**http://fhir_server**

    deactivate EHR
    activate Smart App
    Smart App-->FHIR Resource API: Get http://fhir_server** /.well-known/smart-configuration**
    Smart App->Smart Proxy:Redirect to [/auth?launch=**<launch_context>**&client_id=**client-id**& response_type=**code**&state=**state**&scope=**patient/*.cruds**& redirect_uri=**http://smart-app/redir**]
    deactivate Smart App
    activate Smart Proxy
    Smart Proxy->Smart Proxy:Validate **redirect_uri** by **client_id**, and store **state** and decrypted **launch_context** based on random **new-state**
    Smart Proxy->Keycloak:Redirect to Keycloak login page [/auth?grant_type=**code**&state=**new-state**& scope=**patient/*.cruds**& redirect_uri=**http://smart-proxy/receive**]
    deactivate Smart Proxy
    activate Keycloak


    Keycloak->External Identity Provider:OAuth2
    deactivate Keycloak
    activate External Identity Provider
    External Identity Provider-->User:Enter credentials/Grant Permission
    External Identity Provider->Keycloak:OAuth2
    deactivate External Identity Provider

    activate Keycloak

    Keycloak->User:Show Grant screen
    deactivate Keycloak
    activate User
    User->Keycloak:Allow requested scopes
    deactivate User
    activate Keycloak
    Keycloak->Smart Proxy:Response with code http://smart-proxy/receive?**code=c**& **state=new-state**
    deactivate Keycloak
    activate Smart Proxy
    Smart Proxy->Smart Proxy:Retrieve original **redirect_uri** and **state** by **new-state** and update **launch_context** with **code**
    Smart Proxy->Smart App:Redirect with code https://smart-app/redir?**code=c**&**state=state**
    deactivate Smart Proxy
    activate Smart App
    Smart App->Smart Proxy:Exchange **code** for token
    deactivate Smart App
    activate Smart Proxy
    Smart Proxy->Smart Proxy:Retrieve original **launch_context** based on **code**

    Smart Proxy-->Keycloak:Update user custom attributes from **launch_context** data (patient/encounter/tenant)
    Smart Proxy->Keycloak:Exchange code for token
    activate Keycloak
    note left of Keycloak:Map patient/encounter/tenant user custom attributes to claim(s)
    Keycloak->Smart Proxy:Return **access_token**
    deactivate Keycloak

    Smart Proxy->Smart Proxy:Clear stored **launch_context** data

    Smart Proxy->Smart App:Return **access_token**
    deactivate Smart Proxy

    activate Smart App
    Smart App->FHIR Resource API:Request /Observation and /Patient/1234 with **access_token**
    deactivate Smart App
    activate FHIR Resource API

 
    FHIR Resource API->FHIR Resource API:Validate scopes from token
    FHIR Resource API->Smart App:Return Observations and Patient
    deactivate FHIR Resource API
    activate Smart App
    Smart App->User:Show patient's data
    deactivate Smart App

```

### Running the application

The project requires .NET 8.0 SDK or later to build and uses .NET Aspire orchestration which requires a compatible container runtime such as Docker or Podman.

Have the `SmartOnFhirKeycloakProxy.AppHost` project set as startup project and run it. In the application dashboard, run the link for the `SmartOnFhirKeycloakProxy.ApiService` project which will link to the Rapidoc page.
Select the appropriate scopes and click the Get Token button.

Available scopes for client_id `ehr-app`: `user/Appointment.cruds`

Available scopes for client_id `smart-app`: `launch/patient`, `patient/Appointmet.crus`

Available users: `user1`, `user2`, `adm1` and `adm2` - all have the password `test`. 
