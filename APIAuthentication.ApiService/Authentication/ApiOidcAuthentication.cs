using Microsoft.IdentityModel.Tokens;

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
            jwtOptions.Audience = "account";
            jwtOptions.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
            jwtOptions.SaveToken = true;

            jwtOptions.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = $"{authServerUrl}realms/{realm}",
                ValidateAudience = true,
                ValidAudience = "account",
                ValidateLifetime = true
            };
        });

        return services;
    }
}

//jwtOptions.Events = new JwtBearerEvents
//{
//    //OnMessageReceived = context =>
//    //{
//    //    var accessToken = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
//    //    Debug.WriteLine($"Access Token: {accessToken}");

//    //    // Faça algo com o token de acesso aqui, se necessário
//    //    return Task.CompletedTask;
//    //},
//    OnTokenValidated = context =>
//    {
//        var claimsIdentity = context.Principal!.Identity as ClaimsIdentity;
//        var userClaims = claimsIdentity?.Claims;

//        foreach (var claim in userClaims!)
//        {
//            Debug.WriteLine($"{claim.Type} :{claim.Value}");
//        }
//        return Task.CompletedTask;
//    }
//};

// como acessar o access token por aqui (authentication prop)?
// não é necessário, no claims identity já tem as roles, mas poderia acessar pelo contexto ou header
// via httpContext.getoken("access_token");