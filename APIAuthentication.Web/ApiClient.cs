using Flurl.Http;
using System.Diagnostics;

namespace APIAuthentication.Web;

public class ApiClient
{
    private readonly FlurlClient client;

    public ApiClient()
    {
        Debug.WriteLine("CLIENT --------------------");
        Debug.WriteLine($"{TokenProvider.AccessToken}");
        Debug.WriteLine("--------------------");

        client = new FlurlClient("https://localhost:7573")
            // todo olhar implementa��o para testar as requisi��es
            .WithOAuthBearerToken(TokenProvider.AccessToken)
            .WithHeader("Content-Type", "application/json")
            .WithSettings(x => x.JsonSerializer = new Flurl.Http.Newtonsoft.NewtonsoftJsonSerializer());
    }

    public async Task<string> GetString()
    {
        // todo retornar um response�para visualiar o conte�do do header
        // todo testar acesso a api pelo postman
        return await client.Request().AppendPathSegment("foo").GetStringAsync();
    }
}