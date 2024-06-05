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
            // todo olhar implementação para testar as requisições
            .WithOAuthBearerToken(TokenProvider.AccessToken)
            .WithHeader("Content-Type", "application/json")
            .WithSettings(x => x.JsonSerializer = new Flurl.Http.Newtonsoft.NewtonsoftJsonSerializer());
    }

    public async Task<string> GetString()
    {
        // todo retornar um response´para visualiar o conteúdo do header
        // todo testar acesso a api pelo postman
        return await client.Request().AppendPathSegment("foo").GetStringAsync();
    }
}