using APIAuthentication.Web.Components.Authentication.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Diagnostics;

namespace APIAuthentication.Web.Components.Authentication.Management;

// todo
// reestruturar o script
// separar os eventos
// estruturar log na classe Program.cs
public static class OidcAuthentication
{
    public static IServiceCollection AddOidcAuthentication(this IServiceCollection services, IHostApplicationBuilder builder)
    {
        const int https = 443;
        var configuration = builder.Configuration;
        var keycloakConfig = configuration.GetRequiredSection("Keycloak") ?? throw new InvalidOperationException("Keycloak not configured!");
        var authServerUrl = keycloakConfig["auth-server-url"];
        var realm = keycloakConfig["realm"];
        var resource = keycloakConfig["resource"];
        var pathBase = configuration.GetValue<string>("PathBase") ?? throw new InvalidOperationException("Pathbase not configured!");

        JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = OpenIdConnectDefaults.AuthenticationScheme;
            options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.AccessDeniedPath = new PathString($"{pathBase}/403");
            options.Cookie.Name = "__Host-blazor";
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.EventsType = typeof(CookieEvents);
        })
        .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            ConfigureIdentityProvider(builder, options, authServerUrl, realm, resource, pathBase);
            ForceHttpsOnRedirectToLogin(options, https);
            ForceHttpsOnRedirectToLogOut(options, https);
            ForceHttpsOnLogOutCallback(options, https);
            HandleRemoteFailure(options, pathBase);
        });

        services.AddOpenIdConnectAccessTokenManagement().AddBlazorServerAccessTokenManagement<ServerSideTokenStore>();
        services.AddTransient<CookieEvents>();
        services.AddTransient<OidcEvents>();
        services.AddTransient<IClaimsTransformation, CustomClaimsTransformation>();
        services.AddCascadingAuthenticationState();
        //services.ConfigureCookieOidcRefresh(CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);

        return services;
    }

    private static void ConfigureIdentityProvider(IHostApplicationBuilder builder, OpenIdConnectOptions options, string? authServerUrl, string? realm, string? resource, string pathBase)
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.Authority = $"{authServerUrl}realms/{realm}";
        options.ClientId = resource;
        options.ResponseType = OpenIdConnectResponseType.Code;
        //options.ResponseMode = "query";
        options.SaveTokens = true;
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        options.CallbackPath = new PathString($"{pathBase}/signin-oidc");
        options.SignedOutCallbackPath = new PathString($"{pathBase}/signout-callback-oidc");
        options.RemoteSignOutPath = new PathString($"{pathBase}/signout-oidc");
        options.SignedOutRedirectUri = pathBase;
        options.Scope.Add(OpenIdConnectScope.OpenIdProfile);
        options.Scope.Add(OpenIdConnectScope.OfflineAccess);
        options.Scope.Add("roles");
        options.Scope.Add("api.fullaccess");
        options.GetClaimsFromUserInfoEndpoint = true;
        options.ClaimActions.DeleteClaims("auth_time", "typ", "session_state", "sid", "preferred_username", "given_name", "family_name");
        options.ClaimActions.Remove("aud");
        options.ClaimActions.MapUniqueJsonKey("resource_access", "resource_access");
        options.TokenValidationParameters.NameClaimType = JwtRegisteredClaimNames.Name;
        options.TokenValidationParameters.RoleClaimType = "role";
        options.EventsType = typeof(OidcEvents);
    }

    private static void ForceHttpsOnRedirectToLogin(OpenIdConnectOptions options, int httpsPort)
    {
        options.Events.OnRedirectToIdentityProvider = context =>
        {
            if (context.Request.IsHttps) { return Task.CompletedTask; }

            var request = context.Request;
            var newRedirectUri = new UriBuilder()
            {
                Scheme = "https",
                Host = request.Host.Host,
                Port = request.Host.Port ?? httpsPort,
                Path = context.Options.CallbackPath.ToString(),
            };

            context.ProtocolMessage.RedirectUri = newRedirectUri.ToString();
            context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.Replace("http://", "https://");

            return Task.CompletedTask;
        };
    }

    private static void ForceHttpsOnRedirectToLogOut(OpenIdConnectOptions options, int httpsPort)
    {
        options.Events.OnRedirectToIdentityProviderForSignOut = context =>
        {
            if (context.Request.IsHttps) { return Task.CompletedTask; }

            var request = context.Request;
            var newRedirectUri = new UriBuilder()
            {
                Scheme = "https",
                Host = request.Host.Host,
                Port = request.Host.Port ?? httpsPort,
                Path = context.Options.SignedOutCallbackPath.ToString(),
            };

            context.ProtocolMessage.PostLogoutRedirectUri = newRedirectUri.ToString();
            context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.Replace("http://", "https://");

            return Task.CompletedTask;
        };
    }

    private static void ForceHttpsOnLogOutCallback(OpenIdConnectOptions options, int httpsPort)
    {
        options.Events.OnSignedOutCallbackRedirect = context =>
        {
            if (context.Request.IsHttps) { return Task.CompletedTask; }

            var request = context.Request;
            var newRedirectUri = new UriBuilder()
            {
                Scheme = "https",
                Host = request.Host.Host,
                Port = request.Host.Port ?? httpsPort,
                Path = context.Options.SignedOutCallbackPath.ToString(),
            };

            context.Response.Redirect(newRedirectUri.ToString());
            context.Options.Authority = context.Options.Authority?.Replace("http://", "https://");

            return Task.CompletedTask;
        };
    }

    private static void HandleRemoteFailure(OpenIdConnectOptions options, string pathBase)
    {
        options.Events.OnRemoteFailure = async context =>
        {
            Debug.WriteLine(
                $"------------------\n" +
                $"Logging: \n" +
                $"Message: {context.Failure?.Message}\n" +
                $"Exception: {context.Failure?.ToString()}\n" +
                $"Source app: {context.Failure?.Source}\n" +
                $"InnerException: {context.Failure?.InnerException}\n" +
                $"StackTrace: {context.Failure?.StackTrace}" +
                $"------------------"
            );

            if ((bool)context.Failure?.Message.Contains("Offline tokens", StringComparison.OrdinalIgnoreCase)!)
            {
                //todo
                //estudar exclusão dos cookies e o momento
                //context.Response.Cookies.Delete(".AspNetCore.Cookies");
                // criar pagina para erro 405
                await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await context.HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, context.HttpContext.AuthenticateAsync().Result?.Properties);

                //try
                //{
                //    var postResponse = await "https://localhost:7100/api-auth/authentication/logout".PostAsync();
                //    var location = postResponse.Headers.FirstOrDefault("Location");
                //    var getResponse = await location.PostAsync();
                //    var message = Uri.EscapeDataString("Usuário ou cliente sem permissão para acesso offline");
                //    context.Response.Redirect($"{pathBase}/403/{message}");
                //}
                //catch (FlurlHttpTimeoutException ex)
                //{
                //}
                //catch (FlurlHttpException ex)
                //{
                //}
                //catch (Exception)
                //{
                //    throw;
                //}

                context.HandleResponse();
                return;
            }

            if (context.Request.Path.Equals($"{pathBase}/signin-oidc"))
            {
                context.HandleResponse();
                context.Response.Redirect(pathBase);
            }
            return;
        };
    }
}