using Microsoft.AspNetCore.Authorization;

namespace APIAuthentication.Authorization;

public static class AuthorizationPolicies
{
    public static AuthorizationPolicy IsAdmin()
    {
        return new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .RequireClaim("role", "admin")
            .Build();
    }
}
