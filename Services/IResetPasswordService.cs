using BackendAuth.Models;

namespace BackendAuth.Services
{
    public interface IResetPasswordService
    {
        Task<AuthResult> RequestResetPasswordAsync(string email);
        Task<AuthResult> ResetPasswordAsync(UserResetPasswordRequestDto resetRequest);
    }
}