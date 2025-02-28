using BackendAuth.Models;
using BackendAuth.Models.DTOs;
using BackendAuth.Services;
using BackendAuth.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace BackendAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")] // api/authentication
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IResetPasswordService _resetPasswordService;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(
            IAuthService authService,
            IResetPasswordService resetPasswordService,
            UserManager<IdentityUser> userManager,
            ILogger<AuthenticationController> logger)
        {
            _authService = authService;
            _resetPasswordService = resetPasswordService;
            _logger = logger;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(AuthResultHelper.CreateErrorResponse(
                    string.Join(", ", ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage))),
                    HttpStatusCode.BadRequest));
            }

            var result = await _authService.RegisterUserAsync(requestDto, HttpContext);
            return StatusCode((int)result.Status, result);
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            var result = await _authService.ConfirmEmailAsync(userId, code);
            return StatusCode((int)result.Status, result);
        }

        [HttpPost("RequestResetPassword")]
        public async Task<IActionResult> RequestResetPassword([FromBody] UserRequireResetPasswordRequestDto resetRequest)
        {
            var result = await _resetPasswordService.RequestResetPasswordAsync(resetRequest.Email);
            return StatusCode((int)result.Status, result);
        }

        [HttpPost("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] UserResetPasswordRequestDto resetRequest)
        {
            var result = await _resetPasswordService.ResetPasswordAsync(resetRequest);
            return StatusCode((int)result.Status, result);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] UserAuthenticationRequestDto loginRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(AuthResultHelper.CreateErrorResponse("Invalid Payload", HttpStatusCode.BadRequest));
            }

            var result = await _authService.LoginAsync(loginRequest);
            return StatusCode((int)result.Status, result);
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(AuthResultHelper.CreateErrorResponse("Invalid Payload", HttpStatusCode.BadRequest));
            }

            var result = await _authService.RefreshToken(tokenRequest);
            return StatusCode((int)result.Status, result);
        }
    }
}
