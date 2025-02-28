using BackendAuth.Data;
using BackendAuth.Models;
using BackendAuth.Helpers;
using BackendAuth.Models.DTOs;
using BackendAuth.Configurations;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System;

namespace BackendAuth.Services
{
    public class AuthService : IAuthService
    {
        private readonly ILogger<AuthService> _logger;
        private readonly IEmailService _emailService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly UserContext _context;
        private readonly JwtConfigOptions _jwtConfig;

        public AuthService(
            ILogger<AuthService> logger,
            IEmailService emailService,
            UserManager<IdentityUser> userManager,
            UserContext userContext,
            JwtConfigOptions jwtConfig)
        {
            _logger = logger;
            _emailService = emailService;
            _userManager = userManager;
            _context = userContext;
            _jwtConfig = jwtConfig;
        }

        public async Task<AuthResult> ConfirmEmailAsync(string userId, string code)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
                return AuthResultHelper.CreateErrorResponse("Invalid email confirmation URL", HttpStatusCode.BadRequest);

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return AuthResultHelper.CreateErrorResponse("Invalid email parameters", HttpStatusCode.BadRequest);

            var result = await _userManager.ConfirmEmailAsync(user, code);

            return result.Succeeded
                ? AuthResultHelper.CreateSuccessResponse("Your email has been confirmed!")
                : AuthResultHelper.CreateErrorResponse("Your email is not confirmed, please try again later", HttpStatusCode.InternalServerError);
        }

        public async Task<AuthResult> GenerateJwtTokenAsync(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtConfig.Secret);
            var expiryTime = TimeSpan.TryParse(_jwtConfig.ExpiryTime, out var parsedTime) ? parsedTime : TimeSpan.FromMinutes(15);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.Add(expiryTime),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
                })
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken
            {
                UserId = user.Id,
                Token = GeneralHelper.RandomStringGeneration(24),
                JwtId = token.Id,
                IsUsed = false,
                IsRevoked = false,
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6)
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return AuthResultHelper.CreateSuccessResponseWithToken(jwtToken, refreshToken.Token, "Token generated successfully!");
        }

        public async Task<AuthResult> LoginAsync(UserAuthenticationRequestDto loginRequest)
        {
            var user = await _userManager.FindByEmailAsync(loginRequest.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, loginRequest.Password))
                return AuthResultHelper.CreateErrorResponse("Invalid username or password.", HttpStatusCode.BadRequest);

            if (!user.EmailConfirmed)
                return AuthResultHelper.CreateErrorResponse("Email needs to be confirmed!", HttpStatusCode.BadRequest);

            return await GenerateJwtTokenAsync(user);
        }

        public async Task<AuthResult> RegisterUserAsync(UserRegistrationRequestDto requestDto, HttpContext httpContext)
        {
            if (await _userManager.FindByEmailAsync(requestDto.Email) != null)
                return AuthResultHelper.CreateErrorResponse("Email already exists!", HttpStatusCode.Conflict);

            var newUser = new IdentityUser
            {
                Email = requestDto.Email,
                UserName = requestDto.Name,
                EmailConfirmed = false
            };

            var isCreated = await _userManager.CreateAsync(newUser, requestDto.Password);
            if (!isCreated.Succeeded)
                return AuthResultHelper.CreateErrorResponse("Failed to create account", HttpStatusCode.BadRequest);

            var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
            var confirmationUrl = _emailService.GenerateConfirmationUrl(newUser.Id, emailConfirmationToken, httpContext);

            var body = $"Please confirm your email address by clicking <a href=\"{confirmationUrl}\">here</a>.";
            var subject = "Email Verification Waves";

            var result = await _emailService.SendVerificationEmailAsync(body, newUser.Email, subject);
            return result
                ? AuthResultHelper.CreateSuccessResponse("Email Sent successfully!")
                : AuthResultHelper.CreateSuccessResponse("Email Created, but not sent Successfully!");
        }

        public async Task<AuthResult> RefreshToken(TokenRequest tokenRequest)
        {
            var result = await VerifyAndGenerateRefreshToken(tokenRequest);
            return result ?? AuthResultHelper.CreateErrorResponse("Invalid Token", HttpStatusCode.BadRequest);
        }

        private async Task<AuthResult> VerifyAndGenerateRefreshToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _jwtConfig.TokenValidationParameters, out var validatedToken);

                if (validatedToken is JwtSecurityToken jwtSecurityToken &&
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return AuthResultHelper.CreateErrorResponse("Incorrect header", HttpStatusCode.BadRequest);
                }

                var expiryDate = GeneralHelper.UnixTimestampToDateTime(
                    long.Parse(tokenInVerification.Claims.First(x => x.Type == JwtRegisteredClaimNames.Exp).Value));

                if (expiryDate < DateTime.UtcNow)
                    return AuthResultHelper.CreateErrorResponse("Token expired", HttpStatusCode.BadRequest);

                var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);
                if (storedToken == null || storedToken.IsUsed || storedToken.IsRevoked || storedToken.ExpiryDate < DateTime.UtcNow)
                    return AuthResultHelper.CreateErrorResponse("Invalid Token!", HttpStatusCode.BadRequest);

                storedToken.IsUsed = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenerateJwtTokenAsync(dbUser);
            }
            catch (Exception e)
            {
                _logger.LogError($"Token verification error: {e.Message}");
                return AuthResultHelper.CreateErrorResponse("Server Error", HttpStatusCode.InternalServerError);
            }
        }
    }
}
