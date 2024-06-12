// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace APIAuthentication.Web.Components.Authentication.Events;

public class CookieEvents(IUserTokenStore store) : CookieAuthenticationEvents
{
    private readonly IUserTokenStore store = store;

    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var token = await store.GetTokenAsync(context.Principal!);
        if (token.IsError)
        {
            context.RejectPrincipal();
        }

        await base.ValidatePrincipal(context);
    }

    public override async Task SigningOut(CookieSigningOutContext context)
    {
        await context.HttpContext.RevokeRefreshTokenAsync();

        await base.SigningOut(context);
    }
}