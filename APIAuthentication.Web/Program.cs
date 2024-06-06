using APIAuthentication.Web;
using APIAuthentication.Web.Components;
using APIAuthentication.Web.Components.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire components.
builder.AddServiceDefaults();
builder.AddRedisOutputCache("cache");

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddOidcAuthentication(builder);
builder.Services.AddAuthorization();

builder.Services.AddScoped<ApiClient>();
builder.Services.AddHttpContextAccessor();

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