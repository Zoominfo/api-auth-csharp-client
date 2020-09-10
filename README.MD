# Zoominfo API Auth C# Client

#### NuGet Package
https://www.nuget.org/packages/Zoominfo.API.Authentication.Client.NetCore


#### Get access token using client id and private key
```
Com.Zoominfo.Api.AuthClient authClient = new Com.Zoominfo.Api.AuthClient.AuthClient("username", "clientId", "privateKey");
string accessToken = authClient.getAccessToken();
```
##### Note: The private key String should be in the following format
```
"-----BEGIN PRIVATE KEY-----\n" +  
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCTLgTQx325tynx\n" +  
"9g2c/Zcy4e+MVW9ZiN4/CES2wP/iYNQTeTPwzl1JCGGY37n9zwj/cdMNbjWaIHmA\n" +  
"jjMpFjepXpZ8m80TOQjRYWrPAhW1qGEZ6CsNeiXi5uQ6H932b4gFG1YCaQG5AqFT\n" +  
"01IkpHLEFHQNJ49pQ7C8G/k=\n" +  
"-----END PRIVATE KEY-----";
```

#### Get access token using username and password
```
Com.Zoominfo.Api.AuthClient authClient = new Com.Zoominfo.Api.AuthClient("username", "password");
string accessToken = authClient.getAccessToken();
```