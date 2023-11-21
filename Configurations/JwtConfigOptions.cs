using Microsoft.IdentityModel.Tokens;

namespace BackendAuth.Configurations
{
    public class JwtConfigOptions
    {
        public string Secret { get; set; }
        public string ExpiryTime { get; set; }
        public TokenValidationParameters TokenValidationParameters { get; set; }
        public TimeSpan ExpiryTimeSpan => TimeSpan.Parse(ExpiryTime);
    }
}