using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecurityAgent.StatusApi;
using SecurityAgent.Worker;

// Órdenes del instalador (--make-manifest / --verify-manifest): se ejecutan y salen sin arrancar el servicio.
var cliConfig = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: true).AddJsonFile("appsettings.Production.json", optional: true)
    .AddEnvironmentVariables().Build();
if (Cli.TryRun(args, AppContext.BaseDirectory, cliConfig, Console.Out) is { } exitCode) return exitCode;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory });
builder.Services.AddWindowsService(o => o.ServiceName = "SecurityAgent");
builder.Services.AddSecurityAgent(builder.Configuration);

var options = AgentComposition.BindOptions(builder.Configuration);
builder.WebHost.UseUrls(options.StatusApi.Listen);

var app = builder.Build();

// La API de estado es opcional para la protección: sin token no se publica (falla cerrada) pero el monitor sigue funcionando.
if (string.IsNullOrWhiteSpace(options.StatusApi.Token))
    app.Logger.LogError("StatusApi:Token vacío: la API de estado queda DESHABILITADA. El monitor sigue protegiendo.");
else
    app.MapStatusApi(app.Services.GetRequiredService<StatusService>(), options.StatusApi);

ResourceGovernor.Apply(options.Limits, app.Logger);
app.Run();
return 0;
