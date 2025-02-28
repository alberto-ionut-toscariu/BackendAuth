using System.ComponentModel.DataAnnotations;

namespace BackendAuth.Configurations
{
    public class EmailConfigOptions
    {
        [Required(ErrorMessage = "SenderEmail is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format for SenderEmail.")]
        public string SenderEmail { get; init; }

        [Required(ErrorMessage = "ApiKey is required.")]
        public string ApiKey { get; init; }
    }
}