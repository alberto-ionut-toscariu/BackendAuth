using BackendAuth.Data;
using BackendAuth.Models;
using BackendAuth.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace BackendAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")] // api/authentication
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IResetPasswordService _resetPasswordService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly UserContext _context;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController
        (
            IAuthService authService,
            IResetPasswordService resetPasswordService,
            UserManager<IdentityUser> userManager,
            IConfiguration configuration,
            UserContext userContext,
            ILogger<AuthenticationController> logger
        )
        {
            _authService = authService;
            _resetPasswordService = resetPasswordService;
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
                    Messages = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage)).ToList()
                });
            }
            var result = await _authService.RegisterUserAsync(requestDto, HttpContext);
            return result.Status switch
            {
                200 => Ok(result),
                400 => BadRequest(result),
                409 => Conflict(result),
                _ => StatusCode(500, result),
            };
        }

        [HttpGet]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            var result = await _authService.ConfirmEmailAsync(userId, code);

            return result.Status switch
            {
                200 => Ok(result),
                400 => BadRequest(result),
                _ => StatusCode(500, result),
            };
        }

        [HttpPost]
        [Route("RequestResetPassword")]
        public async Task<IActionResult> RequestResetPassword([FromBody] UserResetPasswordRequestDto resetRequest)
        {
            var result = await _resetPasswordService.RequestResetPasswordAsync(resetRequest.Email);
            return result.Status switch
            {
                200 => Ok(result),
                400 => BadRequest(result),
                _ => StatusCode(500, result),
            };
        }

        [HttpPost("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] UserResetPasswordRequestDto resetRequest)
        {
            var result = await _resetPasswordService.ResetPasswordAsync(resetRequest);
            return result.Status switch
            {
                200 => Ok(result),
                400 => BadRequest(result),
                _ => StatusCode(500, result),
            };
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserAuthenticationRequestDto loginRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthResult
                {
                    Success = false,
                    Messages = new List<string> { "Invalid Payload" }
                });
            }
            var result = await _authService.LoginAsync(loginRequest);
            return result.Status switch
            {
                200 => Ok(result),
                400 => BadRequest(result),
                409 => Conflict(result),
                _ => StatusCode(500, result),
            };
        }
    };
}