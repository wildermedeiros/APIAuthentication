using Microsoft.AspNetCore.Authentication;
using System.Net;

namespace APIAuthentication.Web.Components.Authentication;

public static class StatusCodePagesHandler
{
    public static void UseStatusCodePagesHandler(this IApplicationBuilder app, string pathBase)
    {
        app.UseStatusCodePages(async context =>
        {
            if (context.HttpContext.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
            {
                await context.HttpContext.ChallengeAsync();
            }
        });

        app.UseStatusCodePages(context =>
        {
            if (context.HttpContext.Response.StatusCode == (int)HttpStatusCode.Forbidden)
            {
                context.HttpContext.Response.Redirect($"{pathBase}/403");
            }
            return Task.CompletedTask;
        });

        app.UseStatusCodePages(context =>
        {
            if (context.HttpContext.Response.StatusCode == (int)HttpStatusCode.NotFound)
            {
                context.HttpContext.Response.Redirect($"{pathBase}/404");
            }
            return Task.CompletedTask;
        });
    }
}