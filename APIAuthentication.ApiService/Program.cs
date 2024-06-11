using ApiAuthentication.ApiService.Authentication;
using APIAuthentication.ApiService.Authentication;
using APIAuthentication.Authorization;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire components.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddProblemDetails();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddApiOidcAuthentication(builder);
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("admin", AuthorizationPolicies.IsAdmin());

builder.Services.AddTransient<IClaimsTransformation, CustomClaimsTransformation>();

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
}).RequireAuthorization("admin");

app.Run();