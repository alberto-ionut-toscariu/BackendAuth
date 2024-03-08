using BackendAuth.Configurations;
using BackendAuth.Data;
using BackendAuth.Helpers;
using BackendAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
string connectionString = builder.Configuration.GetConnectionString("Default") ?? "null";
var generalHelper = new GeneralHelper();

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<UserContext>(opt => opt.UseSqlServer(connectionString));
builder.Services.AddLogging(builder =>
{
    builder.AddConsole();
    builder.AddDebug();
});

builder.Services.Configure<JwtConfigOptions>(builder.Configuration.GetSection("JwtConfig"));
builder.Services.Configure<EmailConfigOptions>(builder.Configuration.GetSection("EmailConfig"));
builder.Services.AddSingleton<EmailConfigOptions>(provider =>
    provider.GetRequiredService<IConfiguration>().GetSection("EmailConfig").Get<EmailConfigOptions>());
var jwtConfig = builder.Configuration.GetSection("JwtConfig").Get<JwtConfigOptions>(); // Used for manually injecting - might be better to find alternative
jwtConfig.TokenValidationParameters = generalHelper.GetTokenValidationParameters(jwtConfig);

builder.Services.AddSingleton(jwtConfig);


builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IResetPasswordService, ResetPasswordService>();

builder.Services.AddAuthentication(opt =>
{
    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

})
.AddJwtBearer(jwt =>
{
    jwt.SaveToken = true;
    jwt.TokenValidationParameters = jwtConfig.TokenValidationParameters;
});


builder.Services.AddDefaultIdentity<IdentityUser>(opt =>
{
    opt.SignIn.RequireConfirmedAccount = false;
}).AddEntityFrameworkStores<UserContext>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
