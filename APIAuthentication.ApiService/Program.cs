using ApiAuthentication.ApiService.Authentication;
using APIAuthentication.ApiService.Authentication;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire components.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddProblemDetails();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddApiOidcAuthentication(builder);
builder.Services.AddAuthorization(configure =>
    configure.AddPolicy("admin", policy =>
        policy.RequireRole("admin")));

builder.Services.AddTransient<IClaimsTransformation, CustomClaimsTransformation>();

var app = builder.Build();
var pathBase = builder.Configuration.GetValue<string>("PathBase");

app.UsePathBase(pathBase);

// Configure the HTTP request pipeline.
app.UseExceptionHandler();


app.MapGet("/foo", () =>
{
    return "olá";
}).RequireAuthorization("admin");

app.MapDefaultEndpoints();

app.UseSwagger();
app.UseSwaggerUI();

// todo testar sem esse middleware
app.UseAuthentication();
app.UseAuthorization();

app.Run();
