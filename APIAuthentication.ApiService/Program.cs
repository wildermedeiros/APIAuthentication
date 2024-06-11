using ApiAuthentication.ApiService.Authentication;
using APIAuthentication.ApiService.Authentication;
using APIAuthentication.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire components.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddProblemDetails();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddApiOidcAuthentication(builder);
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("IsAdmin", AuthorizationPolicies.IsAdmin())
    .AddPolicy("HasFullAccess", policy =>
    {
        policy.RequireAuthenticatedUser()
              .RequireClaim("fullaccess", "true");
    })
    .AddPolicy("ExampleRequirement", policy =>
    {
        policy.RequireAuthenticatedUser()
              .AddRequirements(new ExampleRequirement());
    });

var app = builder.Build();
var pathBase = builder.Configuration.GetValue<string>("PathBase");

app.UsePathBase(pathBase);

// Configure the HTTP request pipeline.
app.UseExceptionHandler();

app.MapDefaultEndpoints();

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/foo", () =>
{
    return "olá";
}).RequireAuthorization("IsAdmin", "HasFullAccess", "ExampleRequirement");

app.Run();