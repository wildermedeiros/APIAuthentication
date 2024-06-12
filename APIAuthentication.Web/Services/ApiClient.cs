using Duende.AccessTokenManagement.OpenIdConnect;
using Flurl.Http;
using Microsoft.AspNetCore.Components.Authorization;
using Serilog;

namespace APIAuthentication.Web.Services;

public class ApiClient
{
    private readonly IUserTokenManagementService tokenManagementService;
    private readonly AuthenticationStateProvider authenticationStateProvider;
    private readonly FlurlClient client;
    private readonly IUserTokenStore userTokenStore;

    public ApiClient(IUserTokenManagementService tokenManagementService, AuthenticationStateProvider authenticationStateProvider, IUserTokenStore userTokenStore)
    {
        this.tokenManagementService = tokenManagementService;
        this.authenticationStateProvider = authenticationStateProvider;
        this.userTokenStore = userTokenStore;

        client = new FlurlClient("https://localhost:7573")
        .WithHeader("Content-Type", "application/json")
        .WithSettings(x => x.JsonSerializer = new Flurl.Http.Newtonsoft.NewtonsoftJsonSerializer())
        .BeforeCall(async call =>
        {
            var state = await authenticationStateProvider.GetAuthenticationStateAsync();
            var token = await tokenManagementService.GetAccessTokenAsync(state.User);
            Log.Information("Token from manager: {Token}", token.AccessToken);
            call.Client.WithOAuthBearerToken(token.AccessToken);
        });
    }

    public async Task<string> GetString()
    {
        // todo
        // retornar um response para validar e não quebrar a aplicação
        return await client.Request().AppendPathSegment("foo").GetStringAsync();
    }
}

// todo
// pesquisar o que o timespam.fromminutes faz