using BackendAuth.Configurations;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace BackendAuth.Services
{
    public class EmailService : IEmailService
    {
        private readonly ILogger<EmailService> _logger;
        private readonly LinkGenerator _linkGenerator;
        private readonly EmailConfigOptions _emailConfigOptions;
        private readonly SendGridClient _sendGridClient;

        public EmailService(
            ILogger<EmailService> logger,
            LinkGenerator linkGenerator,
            IOptions<EmailConfigOptions> emailConfigOptions)
        {
            _logger = logger;
            _linkGenerator = linkGenerator;
            _emailConfigOptions = emailConfigOptions.Value;

            if (string.IsNullOrWhiteSpace(_emailConfigOptions.ApiKey))
            {
                throw new ArgumentException("SendGrid API key is missing from configuration.");
            }

            _sendGridClient = new SendGridClient(_emailConfigOptions.ApiKey);
        }

        public async Task<bool> SendVerificationEmailAsync(string body, string email, string subject)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(body) || string.IsNullOrWhiteSpace(subject))
                {
                    _logger.LogWarning("Attempted to send email with missing parameters.");
                    return false;
                }

                var senderEmail = _emailConfigOptions.SenderEmail;

                var from = new EmailAddress(senderEmail, "Waves");
                var to = new EmailAddress(email);
                var msg = MailHelper.CreateSingleEmail(from, to, subject, "", body);

                var response = await _sendGridClient.SendEmailAsync(msg);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Failed to send email. StatusCode: {StatusCode}", response.StatusCode);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending email: {ExceptionMessage}", ex.Message);
                return false;
            }
        }

        public string GenerateConfirmationUrl(string userId, string emailConfirmationToken, HttpContext httpContext)
        {
            try
            {
                if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(emailConfirmationToken) || httpContext == null)
                {
                    _logger.LogError("Invalid parameters provided for GenerateConfirmationUrl.");
                    return string.Empty;
                }

                var confirmationUrl = _linkGenerator.GetUriByAction(
                    httpContext: httpContext,
                    action: "ConfirmEmail",
                    controller: "Authentication",
                    values: new { userId, code = emailConfirmationToken },
                    scheme: httpContext.Request.Scheme);

                return confirmationUrl ?? string.Empty;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating confirmation URL for userId: {UserId}", userId);
                return string.Empty;
            }
        }
    }
}
