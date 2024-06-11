using Duende.AccessTokenManagement.OpenIdConnect;
using Flurl.Http;
using Microsoft.AspNetCore.Components.Authorization;
using Serilog;

namespace APIAuthentication.Web;

public class ApiClient(
    IHttpContextAccessor httpContextAccessor,
    IUserTokenManagementService tokenManagementService,
    AuthenticationStateProvider authenticationStateProvider)
{
    private readonly IHttpContextAccessor httpContextAccessor = httpContextAccessor;
    private readonly IUserTokenManagementService tokenManagementService = tokenManagementService;
    private readonly AuthenticationStateProvider authenticationStateProvider = authenticationStateProvider;

    private readonly FlurlClient client = new FlurlClient("https://localhost:7573")
        .WithHeader("Content-Type", "application/json")
        .WithSettings(x => x.JsonSerializer = new Flurl.Http.Newtonsoft.NewtonsoftJsonSerializer());

    public async Task<string> GetString()
    {
        var state = await authenticationStateProvider.GetAuthenticationStateAsync();
        var token = await tokenManagementService.GetAccessTokenAsync(state.User);
        Log.Information(token.AccessToken!);

        // todo retornar um response´para validar e não quebrar a aplicação
        return await client.Request().AppendPathSegment("foo").WithOAuthBearerToken(token.AccessToken!).GetStringAsync();
    }
}