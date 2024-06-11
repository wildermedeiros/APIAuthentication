using Microsoft.AspNetCore.Authorization;

namespace APIAuthentication.ApiService.Authentication;

public class ExampleRequirement : IAuthorizationRequirement
{
    public ExampleRequirement()
    {
    }
}
