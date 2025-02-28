using System.ComponentModel.DataAnnotations;

namespace BackendAuth.Models
{
    public class UserRequireResetPasswordRequestDto
    {
        [Required] public string Email { get; set; }
    }
}