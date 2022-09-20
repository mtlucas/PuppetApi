using Serilog;
using Serilog.Exceptions;
using Serilog.Settings.Configuration;
using System.Runtime.InteropServices;
using System.Reflection;
using Microsoft.OpenApi.Models;
using PuppetHieraApi.Api.WebHost;

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Add logging - see below
    ConfigureLogging();
    // Add services to the container.
    builder.Host.UseSerilog();
    builder.Services.AddHealthChecks();
    builder.Services.AddControllers();
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(options =>
    {
        options.SwaggerDoc("v1", new OpenApiInfo
        {
            Version = "v1",
            Title = "Puppet Hiera Search API",
            Description = "An ASP.NET Core Web API for searching and retrieving Puppet Hiera data (source of truth)",
            Contact = new OpenApiContact
            {
                Name = "Michael Lucas",
                Url = new Uri("mailto:mike.lucas@wolterskluwer.com")
            },
        });
        options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
        {
            Description = "Add your ApiKey here",
            In = ParameterLocation.Header,
            Name = "ApiKey",
            Type = SecuritySchemeType.ApiKey,
            Scheme = "ApiKeyScheme"
        });
        options.OperationFilter<AuthenticationRequirementsOperationFilter>();
        var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
        options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));
    });

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
        app.UseExceptionHandler("/Home/Error");
    }

    app.UseHttpsRedirection();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapHealthChecks("/health");
    app.UseRouting();
    app.MapControllers();

    app.Run();
    Log.Debug("PuppetHieraApi application started.");
}
catch (Exception ex)
{
    Log.Fatal(ex, "Unhandled startup exception");
}
finally
{
    Log.Information("Shut down complete.");
    Log.CloseAndFlush();
}

void ConfigureLogging()
{
    var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
    var configuration = new ConfigurationBuilder()
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", true)
        .AddEnvironmentVariables()
        .Build();

    Log.Logger = new LoggerConfiguration()
        .ReadFrom.Configuration(configuration)
        .CreateLogger();

    Log.Information("Starting application and logging...");

    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
    {
        Log.Warning("Running on non-Linux OS, this may not work!");
    }
}
