//using Microsoft.AspNetCore.Authentication;
//using Microsoft.AspNetCore.Authentication.Cookies;
//using Microsoft.AspNetCore.Authentication.OpenIdConnect;
//using Microsoft.Extensions.Caching.Distributed;
//using Microsoft.Extensions.Options;
//using Microsoft.IdentityModel.JsonWebTokens;
//using Microsoft.IdentityModel.Protocols.OpenIdConnect;
//using Microsoft.IdentityModel.Tokens;
//using System.Globalization;
//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;

//namespace APIAuthentication.Web;

//public class TokenService(IDistributedCache cache, IHttpContextAccessor httpContextAccessor, 
//    IOptionsMonitor<OpenIdConnectOptions> oidcOptionsMonitor,
//    IOptionsMonitor<CookieAuthenticationOptions> cookieOptionsMonitor)
//{
//    private readonly IDistributedCache cache = cache;
//    private readonly IHttpContextAccessor httpContextAccessor = httpContextAccessor;

//    // get the expiration time before storing
//    public async Task StoreTokenAsync(string key, string token, TimeSpan expiration)
//    {
//        var options = new DistributedCacheEntryOptions
//        {
//            AbsoluteExpirationRelativeToNow = expiration
//        };

//        await cache.SetStringAsync(key, token, options);
//    }

//    public async Task<string> GetStoredTokenAsync(string key)
//    {
//        var token = await cache.GetStringAsync(key);

//        if (string.IsNullOrWhiteSpace(token))
//        {
//            var httpContext = httpContextAccessor.HttpContext ?? 
//                throw new InvalidOperationException("No active HTTP context. This method should be called within a valid HTTP request.");
            
//            var userIdentity = httpContext.User.Identity ?? 
//                throw new InvalidOperationException("No active User Identity");
            
//            if (!userIdentity.IsAuthenticated)
//            {
//                await httpContext.ChallengeAsync();

//                return await GetAccessTokenAsync(httpContext);
//            }
//            else
//            {
//                string accessTokenExpirationTime = await GetAccessTokenExpirationTimeAsync(httpContext);
//                if (IsValid(accessTokenExpirationTime))
//                {
//                    return await GetAccessTokenAsync(httpContext);
//                }
//                else
//                {
//                    ValidateNewToken();
//                }
//            }
//        }

//        return token!;
//    }

//    private async void ValidateNewToken()
//    {
//        var oidcOptions = oidcOptionsMonitor.Get("MicrosoftOidc");
//        var cookieOptions = cookieOptionsMonitor.Get("Cookies");
//    }

//    private async Task<string> GetAccessTokenExpirationTimeAsync(HttpContext? httpContext)
//    {
//        return await httpContext!.GetTokenAsync("expires_at") ?? throw new InvalidOperationException("No access_token was saved");
//    }

//    private async Task<string> GetAccessTokenAsync(HttpContext? httpContext)
//    {
//        return await httpContext!.GetTokenAsync("access_token") ?? throw new InvalidOperationException("No access_token was saved");
//    }

//    private bool IsValid(string? accessTokenExpirationString)
//    {
//        if (!DateTimeOffset.TryParse(accessTokenExpirationString, out var accessTokenExpiration))
//        {
//            throw new InvalidOperationException("Failed to parse the string expiration date");
//        }

//        if (DateTime.UtcNow > accessTokenExpiration.UtcDateTime)
//        {
//            return true;
//        }

//        return false;
//    }
//}

//// todo oque isso faz?
//// httpContext.AuthenticateAsync