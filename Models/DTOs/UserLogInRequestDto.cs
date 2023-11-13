using System.ComponentModel.DataAnnotations;

namespace BackendAuth.Models
{
    public class UserLogInRequestDto
    {
        [Required] public string Email { get; set; }
        [Required] public string Password { get; set; }
    }
}