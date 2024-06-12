using Microsoft.AspNetCore.Authentication.Cookies;

namespace APIAuthentication.Web.Components.Authentication.Unused;

internal static partial class CookieOidcServiceCollectionExtensions
{
    public static IServiceCollection ConfigureCookieOidcRefresh(this IServiceCollection services, string cookieScheme, string oidcScheme)
    {
        services.AddSingleton<CookieOidcRefresher>();
        services.AddOptions<CookieAuthenticationOptions>(cookieScheme).Configure<CookieOidcRefresher>((cookieOptions, refresher) =>
        {
            cookieOptions.Events.OnValidatePrincipal = context =>
                refresher.ValidateOrRefreshCookieAsync(context, oidcScheme);
        });
        return services;
    }
}