using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace APIAuthentication.Web.Components.Authentication;

public static class LoginLogoutEndpoint
{
    public static IEndpointConventionBuilder MapLoginAndLogout(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/authentication");

        group.MapGet("/login", (HttpContext context, string? returnUrl) =>
            TypedResults.Challenge(GetAuthProperties(context, returnUrl))).AllowAnonymous();

        group.MapPost("/logout", (HttpContext context) =>
            TypedResults.SignOut(null, [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

        return group;
    }

    private static AuthenticationProperties GetAuthProperties(HttpContext context, string? returnUrl)
    {
        string pathBase = context.Request.PathBase;

        // Prevent open redirects.
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = pathBase;
        }
        else if (!Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
        {
            returnUrl = new Uri(returnUrl, UriKind.Absolute).PathAndQuery;
        }
        else if (returnUrl[0] != '/')
        {
            returnUrl = $"{pathBase}/{returnUrl}";
        }

        return new AuthenticationProperties { RedirectUri = returnUrl };
    }
}
