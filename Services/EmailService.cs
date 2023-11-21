using SendGrid;
using SendGrid.Helpers.Mail;

namespace BackendAuth.Services
{
    public class EmailService : IEmailService
    {

        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;
        private readonly LinkGenerator _linkGenerator;
        public EmailService(IConfiguration configuration, ILogger<EmailService> logger, LinkGenerator linkGenerator)
        {
            _configuration = configuration;
            _logger = logger;
            _linkGenerator = linkGenerator;
        }
        public async Task<bool> SendVerificationEmailAsync(string body, string email, string subject)
        {
            try
            {
                var apiKey = _configuration.GetSection("EmailConfig:API_KEY").Value;
                var senderEmail = _configuration.GetSection("EmailConfig:SENDER").Value;

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
                scheme: "http");

            return confirmationUrl;
        }
    }
}