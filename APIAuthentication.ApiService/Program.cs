using ApiAuthentication.ApiService.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire components.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddProblemDetails();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddApiOidcAuthentication(builder);
builder.Services.AddAuthorization();

var app = builder.Build();
var pathBase = builder.Configuration.GetValue<string>("PathBase");

app.UsePathBase(pathBase);

// Configure the HTTP request pipeline.
app.UseExceptionHandler();


app.MapGet("/foo", () =>
{
    return "olá";
});

app.MapDefaultEndpoints();

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.Run();
