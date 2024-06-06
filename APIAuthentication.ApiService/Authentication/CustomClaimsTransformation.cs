using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.TagHelpers.Cache;
using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;

namespace APIAuthentication.ApiService.Authentication;

public class CustomClaimsTransformation : IClaimsTransformation
{
    private readonly IConfiguration configuration;
    private readonly string resource;

    public CustomClaimsTransformation(IConfiguration configuration)
    {
        this.configuration = configuration;

        var keycloakConfig = this.configuration.GetRequiredSection("Keycloak") ?? throw new InvalidOperationException("Keycloak not configured!");
        resource = keycloakConfig["resource"]!;
    }

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var claimsIdentity = new ClaimsIdentity(principal.Identity);
        var resourceAccessValues = claimsIdentity.Claims.FirstOrDefault(c => c.Type == $"resource_access")?.Value;

        if (string.IsNullOrEmpty(resourceAccessValues)) return Task.FromResult(principal);

        using var resourceAccess = JsonDocument.Parse(resourceAccessValues);
        bool containsResourceElement = resourceAccess.RootElement.TryGetProperty(resource, out var resourceValues);
        
        if (!containsResourceElement)
            throw new InvalidOperationException($"Verify if the resource_access has a {resource} property");

        var rolesValues = resourceValues.GetProperty("roles");

        foreach (var role in rolesValues.EnumerateArray())
        {
            var roleValue = role.GetString();
            var matchingClaim = GetMatchingRoleClaim(claimsIdentity, roleValue!);

            if (matchingClaim is null && !string.IsNullOrEmpty(roleValue))
            {
                claimsIdentity.AddClaim(new Claim(claimsIdentity.RoleClaimType, roleValue));
            }
        }

        var transformedPrincipal = new ClaimsPrincipal(claimsIdentity);

        Debug.WriteLine("---------------------");
        foreach (var claim in claimsIdentity.Claims)
        {
            Debug.WriteLine($"{claim.Type} : {claim.Value}");
        }
        return Task.FromResult(transformedPrincipal);
    }

    private static Claim GetMatchingRoleClaim(ClaimsIdentity claimsIdentity, string roleValue)
    {
        return claimsIdentity.Claims.FirstOrDefault(claim =>
            claim.Type.Equals(claimsIdentity.RoleClaimType, StringComparison.InvariantCultureIgnoreCase) &&
            claim.Value.Equals(roleValue, StringComparison.InvariantCultureIgnoreCase))!;
    }
}