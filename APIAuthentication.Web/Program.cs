using APIAuthentication.Authorization;
using APIAuthentication.Web;
using APIAuthentication.Web.Components;
using APIAuthentication.Web.Components.Authentication;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .WriteTo.Async(wt => wt.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}", theme: AnsiConsoleTheme.Code))
    .CreateLogger();

// Add service defaults & Aspire components.
builder.AddServiceDefaults();
builder.AddRedisOutputCache("cache");

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddOidcAuthentication(builder);
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("admin", AuthorizationPolicies.IsAdmin());

builder.Services.AddScoped<ApiClient>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddControllers();

var app = builder.Build();
var pathBase = builder.Configuration.GetValue<string>("PathBase");

app.UsePathBase(pathBase);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseAuthorization();

app.UseAntiforgery();

app.UseOutputCache();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
app.MapDefaultEndpoints();

app.UseStatusCodePagesHandler(pathBase!);

app.MapLoginAndLogout().ExcludeFromDescription();

app.Run();