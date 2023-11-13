namespace BackendAuth.Services
{
    public interface IEmailService
    {
        Task<bool> SendVerificationEmailAsync(string body, string email, string subject);
        public string GenerateConfirmationUrl(string userId, string emailConfirmationToken, HttpContext httpContext);
    }
}