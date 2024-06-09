using Flurl.Http;
using Microsoft.AspNetCore.Authentication;

namespace APIAuthentication.Web;

public class ApiClient(IHttpContextAccessor httpContextAccessor)
{
    private readonly IHttpContextAccessor httpContextAccessor = httpContextAccessor;
    private readonly FlurlClient client = new FlurlClient("https://localhost:7573")
            .WithHeader("Content-Type", "application/json")
            .WithSettings(x => x.JsonSerializer = new Flurl.Http.Newtonsoft.NewtonsoftJsonSerializer());

    public async Task<string> GetString()
    {
        var token = await httpContextAccessor.HttpContext!.GetTokenAsync("access_token");

        // todo retornar um response´para validar e não quebrar a aplicação
        return await client.Request().AppendPathSegment("foo").WithOAuthBearerToken(token).GetStringAsync();
    }
}