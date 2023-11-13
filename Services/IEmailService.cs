namespace BackendAuth.Services
{
    public interface IEmailService
    {
        Task<bool> SendVerificationEmailAsync(string body, string email);
        public string GenerateConfirmationUrl(string userId, string emailConfirmationToken, HttpContext httpContext);
    }
}