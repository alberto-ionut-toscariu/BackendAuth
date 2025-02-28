using System.ComponentModel.DataAnnotations;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace BackendAuth.Configurations
{
    public class JwtConfigOptions
    {
        [Required(ErrorMessage = "JWT Secret is required.")]
        [MinLength(32, ErrorMessage = "JWT Secret must be at least 32 characters for security.")]
        public string Secret { get; init; }

        [Required(ErrorMessage = "ExpiryTime is required.")]
        public string ExpiryTime { get; init; }

        public TokenValidationParameters TokenValidationParameters { get; set; }

        public TimeSpan ExpiryTimeSpan
        {
            get
            {
                return TimeSpan.TryParse(ExpiryTime, out var parsedTime)
                    ? parsedTime
                    : TimeSpan.FromHours(1); // Default expiry if not set
            }
        }

        public JwtConfigOptions()
        {
            // Ensure TokenValidationParameters is initialized
            TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Secret ?? "default_secret_key")), // Avoid null errors
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
        }
    }
}