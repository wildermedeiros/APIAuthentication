using Microsoft.AspNetCore.Authentication;
using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;

namespace APIAuthentication.Web.Components.Authentication.Management;

public class CustomClaimsTransformation : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var claimsIdentity = new ClaimsIdentity(principal.Identity);
        var resourceAccessValues = claimsIdentity.Claims.FirstOrDefault(c => c.Type == $"resource_access")?.Value;
        var resource = claimsIdentity.Claims.FirstOrDefault(c => c.Type == "aud")?.Value;

        if (string.IsNullOrEmpty(resourceAccessValues)) return Task.FromResult(principal);

        using var resourceAccess = JsonDocument.Parse(resourceAccessValues);
        bool containsResourceElement = resourceAccess.RootElement.TryGetProperty(resource!, out var resourceValues);

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
        return Task.FromResult(transformedPrincipal);
    }

    private static Claim GetMatchingRoleClaim(ClaimsIdentity claimsIdentity, string roleValue)
    {
        return claimsIdentity.Claims.FirstOrDefault(claim =>
            claim.Type.Equals(claimsIdentity.RoleClaimType, StringComparison.InvariantCultureIgnoreCase) &&
            claim.Value.Equals(roleValue, StringComparison.InvariantCultureIgnoreCase))!;
    }
}