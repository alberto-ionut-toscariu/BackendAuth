using BackendAuth.Data;
using BackendAuth.Models;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using BackendAuth.Helpers;
using BackendAuth.Models.DTOs;
using Microsoft.EntityFrameworkCore;
using BackendAuth.Configurations;
namespace BackendAuth.Services
{
    public class AuthService : IAuthService
    {
        private readonly ILogger<AuthService> _logger;
        private readonly IEmailService _emailService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly UserContext _context;
        private readonly JwtConfigOptions _jwtConfig;
        public AuthService
        (
            ILogger<AuthService> logger,
            IEmailService emailService,
            UserManager<IdentityUser> userManager,
            UserContext userContext,
            JwtConfigOptions jwtConfig
        )
        {
            _logger = logger;
            _emailService = emailService;
            _userManager = userManager;
            _context = userContext;
            _jwtConfig = jwtConfig;
        }

        public async Task<AuthResult> ConfirmEmailAsync(string userId, string code)
        {
            try
            {
                if (userId == null || code == null)
                    return AuthResultHelper.CreateErrorResponse("Invalid email confirmation URL", 400);

                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                    return AuthResultHelper.CreateErrorResponse("Invalid email parameters", 400);

                var result = await _userManager.ConfirmEmailAsync(user, code);

                return result.Succeeded
                    ? AuthResultHelper.CreateSuccessResponse("Your email has been confirmed!")
                    : AuthResultHelper.CreateErrorResponse("Your email is not confirmed, please try again later", 500);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error during email confirmation: {ex.Message}");
                return AuthResultHelper.CreateErrorResponse("Unexpected error from server side", 500);
            }
        }

        public async Task<AuthResult> GenerateJwtTokenAsync(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtConfig.Secret);
            var expiryTimeString = _jwtConfig.ExpiryTime;
            var defaultExpiryTime = TimeSpan.FromMinutes(15);
            var expiryTime = !string.IsNullOrEmpty(expiryTimeString) ? TimeSpan.Parse(expiryTimeString) : defaultExpiryTime;

            //Token descriptor
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Expires = DateTime.UtcNow.Add(expiryTime),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id",user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub,user.Email),
                    new Claim(JwtRegisteredClaimNames.Email,user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat,DateTime.Now.ToUniversalTime().ToString()),
                })
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken
            {
                UserId = user.Id,
                Token = GeneralHelper.RandomStringGeneration(22), // Add a refresh token
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
            {
                // Find user by email
                var user = await _userManager.FindByEmailAsync(loginRequest.Email);

                // Check if the user exists
                if (user == null)
                {
                    return AuthResultHelper.CreateErrorResponse("Invalid username or password.", 400);
                }
                // Check if email is confirmed
                if (!user.EmailConfirmed)
                {
                    return AuthResultHelper.CreateErrorResponse("Email needs to be confirmed!", 400);
                }
                // Check if the password is correct
                var isCorrect = await _userManager.CheckPasswordAsync(user, loginRequest.Password);
                if (!isCorrect)
                {
                    return AuthResultHelper.CreateErrorResponse("Invalid username or password.", 400);
                }

                // Generate and return JWT token upon successful login
                AuthResult jwtToken = await GenerateJwtTokenAsync(user);
                return jwtToken;
            }
        }

        public async Task<AuthResult> RegisterUserAsync(UserRegistrationRequestDto requestDto, HttpContext httpContext)
        {
            var user_exist = await _userManager.FindByEmailAsync(requestDto.Email);
            if (user_exist != null)
            {
                return AuthResultHelper.CreateErrorResponse("Email already exists!", 409);
            }
            var newUser = new IdentityUser()
            {
                Email = requestDto.Email,
                UserName = requestDto.Name,
                EmailConfirmed = false
            };

            var is_created = await _userManager.CreateAsync(newUser, requestDto.Password);
            if (is_created.Succeeded)
            {
                var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                var confirmationUrl = _emailService.GenerateConfirmationUrl(newUser.Id, emailConfirmationToken, httpContext);

                var body = $"Please confirm your email address by clicking the following link: <a href=\"{confirmationUrl}\">Click Here</a>";
                var subject = "Email Verification Waves";

                var result = await _emailService.SendVerificationEmailAsync(body, newUser.Email, subject);
                return result
                 ? AuthResultHelper.CreateSuccessResponse("Email Sent successfully!")
                 : AuthResultHelper.CreateSuccessResponse("Email Created, but not sent Successfully!");
            }
            return AuthResultHelper.CreateErrorResponse("Failed to create account", 400);
        }

        public async Task<AuthResult> RefreshToken(TokenRequest tokenRequest)
        {
            var result = await VerifyAndGenerateRefreshToken(tokenRequest);
            if (result == null)
            {
                return AuthResultHelper.CreateErrorResponse("Invalid Token", 400);
            }
            return result;
        }

        private async Task<AuthResult> VerifyAndGenerateRefreshToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                //_tokenValidationParameters.ValidateLifetime = false; //question this!
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _jwtConfig.TokenValidationParameters, out var validatedToken);

                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                    if (!result) return AuthResultHelper.CreateErrorResponse("Incorrect header", 400);
                }
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
                var expiryDate = GeneralHelper.UnixTimestampToDateTime(utcExpiryDate);

                if (expiryDate >= DateTime.Now)
                {
                    return AuthResultHelper.CreateErrorResponse("Token expired", 400);
                }

                var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);
                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
                if (storedToken == null || storedToken.IsUsed || storedToken.IsRevoked || storedToken.ExpiryDate < DateTime.UtcNow || storedToken.JwtId != jti)
                    return AuthResultHelper.CreateErrorResponse("Invalid Token!", 400);

                storedToken.IsUsed = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenerateJwtTokenAsync(dbUser);

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return AuthResultHelper.CreateErrorResponse("Server Error", 500);
            }
        }
    }
}