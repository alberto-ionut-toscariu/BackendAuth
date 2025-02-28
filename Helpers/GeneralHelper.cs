using System.Text;
using BackendAuth.Configurations;
using Microsoft.IdentityModel.Tokens;

namespace BackendAuth.Helpers
{
    public static class GeneralHelper
    {
        private static readonly Random _random = new();
        public static string RandomStringGeneration(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz_";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[_random.Next(s.Length)]).ToArray());
        }

        public static DateTime UnixTimestampToDateTime(long unixTimeStamp)
        {
            return DateTimeOffset.FromUnixTimeSeconds(unixTimeStamp).UtcDateTime;
        }

        public static TokenValidationParameters GetTokenValidationParameters(JwtConfigOptions jwtConfig)
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
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
        }
    }
}