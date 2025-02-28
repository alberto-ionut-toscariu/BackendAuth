using BackendAuth.Configurations;
using BackendAuth.Data;
using BackendAuth.Helpers;
using BackendAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;

var builder = WebApplication.CreateBuilder(args);

//  Connection string
string connectionString = builder.Configuration.GetConnectionString("Default");
if (string.IsNullOrEmpty(connectionString))
{
    throw new InvalidOperationException("Database connection string is missing.");
}

// Logging 
builder.Logging.AddConsole();
builder.Logging.AddDebug();

// Services Configuration
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<UserContext>(opt => opt.UseSqlServer(connectionString));

// Configure Jwt and Email options 
builder.Services.Configure<JwtConfigOptions>(builder.Configuration.GetSection("JwtConfig"));
builder.Services.Configure<EmailConfigOptions>(builder.Configuration.GetSection("EmailConfig"));

// Validate JWT Configuration at Startup
var serviceProvider = builder.Services.BuildServiceProvider();
var jwtConfig = serviceProvider.GetRequiredService<IOptions<JwtConfigOptions>>().Value;

// Manually validate the JWT configuration
var validationContext = new ValidationContext(jwtConfig);
var validationResults = new List<ValidationResult>();

if (!Validator.TryValidateObject(jwtConfig, validationContext, validationResults, true))
{
    throw new InvalidOperationException($"Invalid JWT Configuration: {string.Join(", ", validationResults.Select(r => r.ErrorMessage))}");
}

// Use a factory method to set up JWT options
builder.Services.AddSingleton(provider =>
{
    var config = provider.GetRequiredService<IOptions<JwtConfigOptions>>().Value;
    config.TokenValidationParameters = GeneralHelper.GetTokenValidationParameters(config);
    return config;
});

// Dependency Injection for Services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IResetPasswordService, ResetPasswordService>();

// Configure Authentication & JWT
builder.Services.AddAuthentication(opt =>
{
    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(jwt =>
{
    jwt.SaveToken = true;
    jwt.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<JwtConfigOptions>>();
            jwt.TokenValidationParameters = options.Value.TokenValidationParameters;
            return Task.CompletedTask;
        }
    };
});

// Identity Configuration
builder.Services.AddDefaultIdentity<IdentityUser>(opt =>
{
    opt.SignIn.RequireConfirmedAccount = false;
}).AddEntityFrameworkStores<UserContext>();

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// Proper Middleware Order
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("AllowAll");
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
