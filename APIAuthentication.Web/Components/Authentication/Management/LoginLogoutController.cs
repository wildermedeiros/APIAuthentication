using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;

namespace APIAuthentication.Web.Components.Authentication.Management;

[Route("/authentication")]
public class LoginLogoutController : ControllerBase
{
    [AllowAnonymous]
    [HttpGet("login")]
    public IActionResult LogIn(string? returnUrl)
    {
        var properties = GetAuthProperties(HttpContext, returnUrl);

        return Challenge(properties);
    }

    [Authorize]
    [HttpPost("logout")]
    public IActionResult LogOut()
    {
        return SignOut(CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);
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