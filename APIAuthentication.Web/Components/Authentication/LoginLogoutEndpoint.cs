﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace APIAuthentication.Web.Components.Authentication;

public static class LoginLogoutEndpoint
{
    public static IEndpointConventionBuilder MapLoginAndLogout(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/authentication");

        group.MapGet("/login", (HttpContext context) =>
            TypedResults.Challenge(GetAuthProperties(context))).AllowAnonymous();

        group.MapPost("/logout", (HttpContext context) =>
            TypedResults.SignOut(GetAuthProperties(context), [CookieAuthenticationDefaults.AuthenticationScheme, "MicrosoftOidc"]));

        return group;
    }

    private static AuthenticationProperties GetAuthProperties(HttpContext context)
    {
        return new AuthenticationProperties { RedirectUri = context.Request.PathBase };
    }
}
