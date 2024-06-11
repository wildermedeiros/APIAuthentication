using Microsoft.AspNetCore.Authorization;

namespace APIAuthentication.ApiService.Authentication;

public class ExampleHandler : AuthorizationHandler<ExampleRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ExampleRequirement requirement)
    {
        // from here I can access
        // the http context from accessor 
        // the repo or other services
        // and return the requirement when succeed

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
