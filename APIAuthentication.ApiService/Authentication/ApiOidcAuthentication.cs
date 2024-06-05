namespace ApiAuthentication.ApiService.Authentication;

public static class ApiOidcAuthentication
{
    public static IServiceCollection AddApiOidcAuthentication(this IServiceCollection services, IHostApplicationBuilder builder)
    {
        var keycloakConfig = builder.Configuration.GetRequiredSection("Keycloak") ?? throw new InvalidOperationException("Keycloak not configured!");
        var authServerUrl = keycloakConfig["auth-server-url"];
        var realm = keycloakConfig["realm"];
        var resource = keycloakConfig["resource"];

        services.AddAuthentication().AddJwtBearer("Bearer", jwtOptions =>
        {
            jwtOptions.Authority = $"{authServerUrl}realms/{realm}";
            jwtOptions.Audience = resource;
            jwtOptions.RequireHttpsMetadata = !builder.Environment.IsDevelopment();

            // todo validar
            //jwtOptions.SaveToken = true;

            // todo pesquisar qual a diferença de utilizar aquelas validações por aqui, no chat gpt
        });

        return services;
    }
}

// como acessar o access token por aqui?
// ao obter acesso
// gerenciar roles
// aplicar roles no identity

//jwtOptions.Events.OnTokenValidated = context =>
//{
//    //AddRoleClaimsToIdentity(context, resource!);
//    return Task.CompletedTask;
//};

//    private static void AddRoleClaimsToIdentity(TokenValidatedContext context, string resource)
//    {
//        var claimsIdentity = context.Principal!.Identity as ClaimsIdentity ??
//            throw new InvalidOperationException("claimsIdentity is null or was not been found, check if the context is available");

//        var accessToken = context;
//        var jwtHandler = new JwtSecurityTokenHandler();
//        var decodedToken = jwtHandler.ReadJwtToken(accessToken) ??
//            throw new InvalidOperationException("The decoded AccessToken is null, please verify how the AccessToken is being extracted and used or check if the authentication has been established successfully");

//        var resourceAccessValues = decodedToken.Claims.FirstOrDefault(c => c.Type == $"resource_access")?.Value;

//        if (string.IsNullOrEmpty(resourceAccessValues)) return;

//        using var resourceAccess = JsonDocument.Parse(resourceAccessValues);
//        bool containsResourceElement = resourceAccess.RootElement.TryGetProperty(resource, out var resourceValues);
//        if (!containsResourceElement)
//            throw new InvalidOperationException($"Verify if the resource_access has a {resource} property");

//        var rolesValues = resourceValues.GetProperty("roles");

//        foreach (var role in rolesValues.EnumerateArray())
//        {
//            var roleValue = role.GetString();
//            var matchingClaim = GetMatchingRoleClaim(claimsIdentity, roleValue!);

//            if (matchingClaim is null && !string.IsNullOrEmpty(roleValue))
//            {
//                claimsIdentity.AddClaim(new Claim(claimsIdentity.RoleClaimType, roleValue));
//            }
//        }
//    }

//    private static Claim GetMatchingRoleClaim(ClaimsIdentity claimsIdentity, string roleValue)
//    {
//        return claimsIdentity.Claims.FirstOrDefault(claim =>
//            claim.Type.Equals(claimsIdentity.RoleClaimType, StringComparison.InvariantCultureIgnoreCase) &&
//            claim.Value.Equals(roleValue, StringComparison.InvariantCultureIgnoreCase))!;
//    }
//}