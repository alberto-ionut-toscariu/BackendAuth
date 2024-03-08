using BackendAuth.Models;
using BackendAuth.Models.DTOs;
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
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController
        (
            IAuthService authService,
            IResetPasswordService resetPasswordService,
            UserManager<IdentityUser> userManager,
            ILogger<AuthenticationController> logger
        )
        {
            _authService = authService;
            _resetPasswordService = resetPasswordService;
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
        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthResult
                {
                    Success = false,
                    Messages = new List<string> { "Invalid Payload" }
                });
            }
            var result = await _authService.RefreshToken(tokenRequest);
            return result.Status switch
            {
                200 => Ok(result),
                400 => BadRequest(result),
                _ => StatusCode(500, result),
            };
        }
    };
}