using System.ComponentModel.DataAnnotations;

namespace BackendAuth.Models
{
    public class UserAuthenticationRequestDto
    {
        [Required] public string Email { get; set; }
        [Required] public string Password { get; set; }
    }
}