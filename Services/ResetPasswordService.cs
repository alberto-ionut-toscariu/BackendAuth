using BackendAuth.Helpers;
using BackendAuth.Models;
using BackendAuth.Services;
using Microsoft.AspNetCore.Identity;
using System.Net;
using Microsoft.Extensions.Logging;

public class ResetPasswordService : IResetPasswordService
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IEmailService _emailService;
    private readonly ILogger<ResetPasswordService> _logger;

    public ResetPasswordService(UserManager<IdentityUser> userManager, IEmailService emailService, ILogger<ResetPasswordService> logger)
    {
        _userManager = userManager;
        _emailService = emailService;
        _logger = logger;
    }

    public async Task<AuthResult> RequestResetPasswordAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            _logger.LogWarning($"Password reset requested for non-existent email: {email}");
            return AuthResultHelper.CreateErrorResponse("User not found", HttpStatusCode.NotFound);
        }

        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        var body = $"This is your reset token: \"{resetToken}\"";
        var subject = "Password Reset Waves";

        var emailSent = await _emailService.SendVerificationEmailAsync(body, email, subject);

        return emailSent
            ? AuthResultHelper.CreateSuccessResponse("Password reset email sent successfully!")
            : AuthResultHelper.CreateErrorResponse("Failed to send password reset email", HttpStatusCode.InternalServerError);
    }

    public async Task<AuthResult> ResetPasswordAsync(UserResetPasswordRequestDto resetRequest)
    {
        var user = await _userManager.FindByEmailAsync(resetRequest.Email);
        if (user == null)
        {
            _logger.LogWarning($"Password reset attempted for non-existent email: {resetRequest.Email}");
            return AuthResultHelper.CreateErrorResponse("User not found", HttpStatusCode.NotFound);
        }

        var result = await _userManager.ResetPasswordAsync(user, resetRequest.ResetToken, resetRequest.NewPassword);
        if (result.Succeeded)
        {
            _logger.LogInformation($"Password reset successful for email: {resetRequest.Email}");
            return AuthResultHelper.CreateSuccessResponse("Password has been successfully reset!");
        }

        _logger.LogError($"Password reset failed for email: {resetRequest.Email}. Errors: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        return AuthResultHelper.CreateErrorResponse("Password reset failed", HttpStatusCode.BadRequest);
    }
}
