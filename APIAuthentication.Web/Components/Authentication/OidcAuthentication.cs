﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc.TagHelpers.Cache;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace APIAuthentication.Web.Components.Authentication;

public static class OidcAuthentication
{
    public static IServiceCollection AddOidcAuthentication(this IServiceCollection services, IHostApplicationBuilder builder)
    {
        // todo create a enum for that
        const string microsoftOidc = "MicrosoftOidc";
        const int https = 443;

        var configuration = builder.Configuration;
        var keycloakConfig = configuration.GetRequiredSection("Keycloak") ?? throw new InvalidOperationException("Keycloak not configured!");
        var authServerUrl = keycloakConfig["auth-server-url"];
        var realm = keycloakConfig["realm"];
        var resource = keycloakConfig["resource"];
        var pathBase = configuration.GetValue<string>("PathBase") ?? throw new InvalidOperationException("Pathbase not configured!");

        services.AddAuthentication(microsoftOidc)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            HandleAccessDeniedRedirect(options, pathBase);
        })
        .AddOpenIdConnect(microsoftOidc, options =>
        {
            ConfigureIdentityProvider(builder, options, authServerUrl, realm, resource, pathBase);
            //ForceHttpsOnRedirectToLogin(options, https);
            //ForceHttpsOnRedirectToLogOut(options, https);
            //ForceHttpsOnLogOutCallback(options, https);
            HandleRemoteFailure(options, pathBase);
        });

        services.ConfigureCookieOidcRefresh(CookieAuthenticationDefaults.AuthenticationScheme, microsoftOidc);
        services.AddCascadingAuthenticationState();

        return services;
    }

    private static void HandleRemoteFailure(OpenIdConnectOptions options, string pathBase)
    {
        options.Events.OnRemoteFailure = context =>
        {
            // todo fazer log disso
            Debug.WriteLine($"OnRemoteFailure\n" +
                $"Message: {context.Failure?.Message}\n" +
                $"Exception: {context.Failure?.ToString()}\n" +
                $"Source app: {context.Failure?.Source}\n" +
                $"InnerException: {context.Failure?.InnerException}\n" +
                $"StackTrace: {context.Failure?.StackTrace}");

            if ((bool)context.Failure?.Message.Contains("Offline tokens", StringComparison.OrdinalIgnoreCase)!)
            {
                // todo estudar exclusão dos cookies e o momento
                //context.Response.Cookies.Delete(".AspNetCore.Cookies");
                // deslogar
                //await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                //await context.HttpContext.SignOutAsync("MicrosoftOidc", new AuthenticationProperties { RedirectUri = pathBase });
                // redirecionar

                var message = Uri.EscapeDataString("Usuário ou cliente sem permissão para acesso offline");
                context.Response.Redirect($"{pathBase}/403/{message}");

                context.HandleResponse();
                return Task.CompletedTask;
            }

            if (context.Request.Path.Equals($"{pathBase}/signin-oidc"))
            {
                context.HandleResponse();
                context.Response.Redirect(pathBase);
            }
            return Task.CompletedTask;
        };
    }

    private static void HandleAccessDeniedRedirect(CookieAuthenticationOptions options, string pathBase)
    {
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.Redirect($"{pathBase}/403");
            return Task.CompletedTask;
        };
    }

    private static void ForceHttpsOnRedirectToLogin(OpenIdConnectOptions options, int httpsPort)
    {
        options.Events.OnRedirectToIdentityProvider = context =>
        {
            var request = context.Request;
            var newRedirectUri = new UriBuilder()
            {
                Scheme = "https",
                Host = request.Host.Host,
                Port = request.Host.Port ?? httpsPort,
                Path = context.Options.CallbackPath.ToString(),
            };

            Debug.WriteLine("OIDC AUTH----------------------");
            Debug.WriteLine($"Logging OnRedirectToIdentityProvider:\n Schema: {newRedirectUri.Scheme}\n Host: {newRedirectUri.Host}\n Port: {newRedirectUri.Port}\n Path: {newRedirectUri.Path}\n URI: {newRedirectUri}");
            Debug.WriteLine("----------------------");

            context.ProtocolMessage.RedirectUri = newRedirectUri.ToString();
            context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.Replace("http://", "https://");

            return Task.CompletedTask;
        };
    }

    private static void ForceHttpsOnRedirectToLogOut(OpenIdConnectOptions options, int httpsPort)
    {
        options.Events.OnRedirectToIdentityProviderForSignOut = context =>
        {
            var request = context.Request;
            var newRedirectUri = new UriBuilder()
            {
                Scheme = "https",
                Host = request.Host.Host,
                Port = request.Host.Port ?? httpsPort,
                Path = context.Options.SignedOutCallbackPath.ToString(),
            };

            Debug.WriteLine("----------------------");
            Debug.WriteLine($"Logging OnRedirectToIdentityProviderForSignOut:\n Schema: {newRedirectUri.Scheme}\n Host: {newRedirectUri.Host}\n Port: {newRedirectUri.Port}\n Path: {newRedirectUri.Path}\n URI: {newRedirectUri}");
            Debug.WriteLine("----------------------");

            context.ProtocolMessage.PostLogoutRedirectUri = newRedirectUri.ToString();
            context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.Replace("http://", "https://");

            return Task.CompletedTask;
        };
    }

    private static void ForceHttpsOnLogOutCallback(OpenIdConnectOptions options, int httpsPort)
    {
        options.Events.OnSignedOutCallbackRedirect = context =>
        {
            var request = context.Request;
            var newRedirectUri = new UriBuilder()
            {
                Scheme = "https",
                Host = request.Host.Host,
                Port = request.Host.Port ?? httpsPort,
                Path = context.Options.SignedOutCallbackPath.ToString(),
            };

            Debug.WriteLine("----------------------");
            Debug.WriteLine($"Logging OnSignedOutCallbackRedirect:\n Schema: {newRedirectUri.Scheme}\n Host: {newRedirectUri.Host}\n Port: {newRedirectUri.Port}\n Path: {newRedirectUri.Path}\n URI: {newRedirectUri}");
            Debug.WriteLine("----------------------");

            context.Response.Redirect(newRedirectUri.ToString());

            context.Options.Authority = context.Options.Authority?.Replace("http://", "https://");

            return Task.CompletedTask;
        };
    }

    private static void ConfigureIdentityProvider(IHostApplicationBuilder builder, OpenIdConnectOptions options, string? authServerUrl, string? realm, string? resource, string pathBase)
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.Authority = $"{authServerUrl}realms/{realm}";
        options.ClientId = resource;
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        options.Scope.Add(OpenIdConnectScope.OpenIdProfile);
        options.MapInboundClaims = false;
        options.CallbackPath = new PathString($"{pathBase}/signin-oidc");
        options.SignedOutCallbackPath = new PathString($"{pathBase}/signout-callback-oidc");
        options.RemoteSignOutPath = new PathString($"{pathBase}/signout-oidc");
        options.TokenValidationParameters.NameClaimType = JwtRegisteredClaimNames.Name;
        options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;
    }
}