using System.Text;
using BackendAuth.Configurations;
using Microsoft.IdentityModel.Tokens;

namespace BackendAuth.Helpers
{
    public class GeneralHelper
    {
        public static string RandomStringGeneration(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz_";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static DateTime UnixTimestampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
            return dateTimeVal;
        }

        public TokenValidationParameters GetTokenValidationParameters(JwtConfigOptions jwtConfig)
        {
            if (string.IsNullOrWhiteSpace(jwtConfig.Secret))
            {
                throw new ArgumentException("JWT secret is not provided or is empty.", nameof(jwtConfig.Secret));
            }
            return new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtConfig.Secret)),
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = true,
                ValidateLifetime = true
            };
        }
    }
}