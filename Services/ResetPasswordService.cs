using BackendAuth.Helpers;
using BackendAuth.Models;
using BackendAuth.Services;
using Microsoft.AspNetCore.Identity;

public class ResetPasswordService : IResetPasswordService
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IEmailService _emailService;
    public ResetPasswordService(UserManager<IdentityUser> userManager, IEmailService emailService)
    {
        _userManager = userManager;
        _emailService = emailService;
    }

    public async Task<AuthResult> RequestResetPasswordAsync(string email)
    {
        var userEmail = await _userManager.FindByEmailAsync(email);
        if (userEmail == null)
        {
            return AuthResultHelper.CreateErrorResponse("User not found", 400);
        }

        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(userEmail);
        var body = $"This is your reset token: \"{resetToken}\"";
        var subject = "Password Reset Waves";

        var result = await _emailService.SendVerificationEmailAsync(body, email, subject);
        return result
                 ? AuthResultHelper.CreateSuccessResponse("Email Sent successfully!")
                 : AuthResultHelper.CreateSuccessResponse("Email Created, but not sent Successfully!");

    }

    public async Task<AuthResult> ResetPasswordAsync(UserResetPasswordRequestDto resetRequest)
    {
        var user = await _userManager.FindByEmailAsync(resetRequest.Email);
        if (user == null)
        {
            return AuthResultHelper.CreateErrorResponse("User not found", 400);
        }

        var result = await _userManager.ResetPasswordAsync(user, resetRequest.ResetToken, resetRequest.NewPassword);
        return result.Succeeded
        ? AuthResultHelper.CreateSuccessResponse("Password has been successfully reset!")
        : AuthResultHelper.CreateSuccessResponse("Password reset has failed!");
    }
}