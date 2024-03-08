using BackendAuth.Configurations;
using Org.BouncyCastle.Asn1;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace BackendAuth.Services
{
    public class EmailService : IEmailService
    {
        private readonly ILogger<EmailService> _logger;
        private readonly LinkGenerator _linkGenerator;
        private readonly EmailConfigOptions _emailConfigOptions;
        public EmailService(ILogger<EmailService> logger, LinkGenerator linkGenerator, EmailConfigOptions emailConfigOptions)
        {
            _logger = logger;
            _linkGenerator = linkGenerator;
            _emailConfigOptions = emailConfigOptions;
        }
        public async Task<bool> SendVerificationEmailAsync(string body, string email, string subject)
        {
            try
            {
                Console.WriteLine(_emailConfigOptions.ApiKey);
                Console.WriteLine(_emailConfigOptions.SenderEmail);
                var apiKey = _emailConfigOptions.ApiKey;
                var senderEmail = _emailConfigOptions.SenderEmail;

                var client = new SendGridClient(apiKey);

                var from = new EmailAddress(senderEmail, "Waves");
                var to = new EmailAddress(email);
                var msg = MailHelper.CreateSingleEmail(from, to, subject, "", body);

                var response = await client.SendEmailAsync(msg);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending email: {ExceptionMessage}", ex.Message);
                return false;
            }
        }

        public string GenerateConfirmationUrl(string userId, string emailConfirmationToken, HttpContext httpContext)
        {
            var confirmationUrl = _linkGenerator.GetUriByAction(
                httpContext: httpContext,
                action: "ConfirmEmail",
                controller: "Authentication",
                values: new { userId = userId, code = emailConfirmationToken },
                scheme: httpContext.Request.Scheme);
            return confirmationUrl;
        }
    }
}