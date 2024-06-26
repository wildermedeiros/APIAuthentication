using APIAuthentication.Authorization;
using APIAuthentication.Web.Components;
using APIAuthentication.Web.Components.Authentication.Management;
using APIAuthentication.Web.Services;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .WriteTo.Async(wt => wt.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}", theme: AnsiConsoleTheme.Code))
    .CreateLogger();
//.CreateBootstrapLogger();

// Add service defaults & Aspire components.
builder.AddServiceDefaults();
builder.AddRedisOutputCache("cache");
builder.AddRedisDistributedCache("cache");

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddOidcAuthentication(builder);
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("admin", AuthorizationPolicies.IsAdmin());

builder.Services.AddTransient<ApiClient>();
builder.Services.AddControllers();

//builder.Services.AddHttpClient("apiClient", client =>
//{
//    client.BaseAddress = new Uri("https://localhost:7573");
//}).AddUserAccessTokenHandler();

//builder.Services.AddHttpClient("idp", client =>
//{
//    client.BaseAddress = new Uri("http://localhost:8080/realms/wilder");
//});

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

//app.UseSerilogRequestLogging();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllers();

app.UseAntiforgery();

app.UseOutputCache();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
app.MapDefaultEndpoints();

app.UseStatusCodePagesHandler(pathBase!);

app.Run();