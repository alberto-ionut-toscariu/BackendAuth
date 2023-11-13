using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BackendAuth.Data;
using BackendAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace BackendAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")] // api/authentication
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly UserContext _context;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(
            UserManager<IdentityUser> userManager,
             IConfiguration configuration,
              UserContext userContext,
              ILogger<AuthenticationController> logger
              )
        {
            _userManager = userManager;
            _configuration = configuration;
            _context = userContext;
            _logger = logger;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
        {
            if (!ModelState.IsValid)
            {
                // Handle validation errors
                return BadRequest(new AuthResult()
                {
                    Success = false,
                    Errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage)).ToList()
                });
            }

            var user_exist = await _userManager.FindByEmailAsync(requestDto.Email);
            if (user_exist != null)
            {
                return Conflict(new AuthResult()
                {
                    Success = false,
                    Errors = new List<string>
                        {
                            "Email already exists!",
                            "Please log in!"
                        }
                });
            }
            var newUser = new IdentityUser()
            {
                Email = requestDto.Email,
                UserName = requestDto.Name,
                EmailConfirmed = false
            };

            var is_created = await _userManager.CreateAsync(newUser, requestDto.Password);
            Console.WriteLine($"Trying to create {requestDto.Email}");

            if (is_created.Succeeded)
            {
                Console.WriteLine($"Succeeded to create {requestDto.Email}");

                var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                var confirmationUrl = Url.Action("ConfirmEmail", "Authentication",
                    new { userId = newUser.Id, code = emailConfirmationToken }, Request.Scheme);
                var body = $"Please confirm your email address by clicking the following link: <a href=\"{confirmationUrl}\">Click Here</a>";

                var result = await SendEmailAsync(body, newUser.Email);
                if (result)
                    return Ok("Please verify your email through the verification email we have just sent!");
                return Ok("Please request an email verification link");

                //AuthResult jwtToken = await GenerateJwtToken(newUser);
                //return Ok(jwtToken);
            }
            else
            {
                Console.WriteLine($"Failed to create {requestDto.Email}");

                return BadRequest(new AuthResult()
                {
                    Success = false,
                    Errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage)).ToList()
                });
            }
        }

        [HttpGet]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
                return BadRequest(new AuthResult
                {
                    Success = false,
                    Errors = new List<string>()
                        {
                            "Invalid email confirmation url"
                        }
                });

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest(new AuthResult
                {
                    Success = false,
                    Errors = new List<string>()
                        {
                            "Invalid email parameters"
                        }
                });

            //code = Encoding.UTF8.GetString(Convert.FromBase64String(code));
            var result = await _userManager.ConfirmEmailAsync(user, code);
            var status = result.Succeeded ? "Thank you for confirming your email" : "Your email is not confirmed, please try again later";
            return Ok(status);
        }


        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLogInRequestDto loginRequest)
        {
            // Check for invalid payload
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthResult
                {
                    Success = false,
                    Errors = new List<string> { "Invalid Payload" }
                });
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(loginRequest.Email);

            // Check if the user exists
            if (user == null)
            {
                return BadRequest(new AuthResult
                {
                    Success = false,
                    Errors = new List<string> { "Invalid username or password." }
                });
            }

            // Check if email is confirmed
            if (!user.EmailConfirmed)
            {
                return BadRequest(new AuthResult
                {
                    Success = false,
                    Errors = new List<string> { "Email needs to be confirmed!" }
                });
            }

            // Check if the password is correct
            var isCorrect = await _userManager.CheckPasswordAsync(user, loginRequest.Password);

            if (!isCorrect)
            {
                return BadRequest(new AuthResult
                {
                    Success = false,
                    Errors = new List<string> { "Invalid username or password." }
                });
            }

            // Generate and return JWT token upon successful login
            AuthResult jwtToken = await GenerateJwtToken(user);
            return Ok(jwtToken);
        }

        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)

        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);
            var expiryTimeString = _configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value;
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

            await _context.SaveChangesAsync();

            return new AuthResult
            {
                Success = true,
                Token = jwtToken,
            };
        }

        private async Task<bool> SendEmailAsync(string body, string email)
        {
            try
            {
                var apiKey = _configuration.GetSection("EmailConfig:API_KEY").Value;
                var senderEmail = _configuration.GetSection("EmailConfig:SENDER").Value;

                var client = new SendGridClient(apiKey);

                var from = new EmailAddress(senderEmail, "Waves");
                var subject = "Email Verification Waves";
                var to = new EmailAddress(email);
                var msg = MailHelper.CreateSingleEmail(from, to, subject, "", body);

                var response = await client.SendEmailAsync(msg);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error sending email: {ex.Message}");
                return false;
            }
        }
    }
};
