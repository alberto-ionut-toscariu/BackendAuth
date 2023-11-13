using System.ComponentModel.DataAnnotations;

namespace BackendAuth.Models
{
    public class UserResetPasswordRequestDto
    {
        [Required] public string Email { get; set; }
        [Required] public string NewPassword { get; set; }
        [Required] public string ResetToken { get; set; }
    }
}