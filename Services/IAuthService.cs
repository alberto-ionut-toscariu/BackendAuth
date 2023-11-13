using BackendAuth.Models;
using Microsoft.AspNetCore.Identity;

namespace BackendAuth.Services
{
    public interface IAuthService
    {
        Task<AuthResult> RegisterUserAsync(UserRegistrationRequestDto requestDto, HttpContext httpContext);
        Task<AuthResult> ConfirmEmailAsync(string userId, string code);
        Task<AuthResult> GenerateJwtTokenAsync(IdentityUser user);
        Task<AuthResult> LoginAsync(UserAuthenticationRequestDto loginRequest);
    }
}