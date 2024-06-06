using Flurl.Http;
using Microsoft.AspNetCore.Authentication;
using System.Diagnostics;

namespace APIAuthentication.Web;

public class ApiClient
{
    private readonly FlurlClient client;
    private readonly IHttpContextAccessor httpContextAccessor;
    public ApiClient(IHttpContextAccessor httpContextAccessor)
    {
        // todo implementar um cache para melhor manipula��o do token
        Debug.WriteLine("CLIENT --------------------");
        Debug.WriteLine($"{TokenProvider.AccessToken}");
        Debug.WriteLine("--------------------");

        this.httpContextAccessor = httpContextAccessor;

        // todo acionar um beforecall para manipular o token
        client = new FlurlClient("https://localhost:7573")
            .WithHeader("Content-Type", "application/json")
            .WithSettings(x => x.JsonSerializer = new Flurl.Http.Newtonsoft.NewtonsoftJsonSerializer());
    }

    public async Task<string> GetString()
    {
        // todo
        // se o acessor for null?
        // se o token n�o for valido?
        // se o token tiver expirado?
        // � poss�vel redirecionar para login?
        var token = await httpContextAccessor.HttpContext!.GetTokenAsync("access_token");

        Debug.WriteLine("TOKEN DO ACESSOR --------------------");
        Debug.WriteLine(token);

        // todo retornar um response�para validar e n�o quebrar a aplica��o
        return await client.Request().AppendPathSegment("foo").WithOAuthBearerToken(token).GetStringAsync();
    }
}