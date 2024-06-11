using Microsoft.AspNetCore.Authorization;

namespace APIAuthentication.ApiService.Authentication;

public class AuthExampleHandlerAttribute : AuthorizeAttribute, IAuthorizationRequirementData
{
    public IEnumerable<IAuthorizationRequirement> GetRequirements()
    {
        return [new ExampleRequirement()];
    }
}