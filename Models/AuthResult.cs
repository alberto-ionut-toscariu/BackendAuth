using System.Net;

namespace BackendAuth.Models
{
    public class AuthResult
    {
        public string Token { get; init; }
        public string RefreshToken { get; init; }
        public bool Success { get; init; }
        public HttpStatusCode Status { get; init; } 
        public List<string> Messages { get; init; } = new();

        public AuthResult(bool success, HttpStatusCode status, string message, string token = null, string refreshToken = null)
        {
            Success = success;
            Status = status;
            Token = token;
            RefreshToken = refreshToken;
            Messages = new() { message };
        }

        public AuthResult(bool success, HttpStatusCode status, List<string> messages, string token = null, string refreshToken = null)
        {
            Success = success;
            Status = status;
            Token = token;
            RefreshToken = refreshToken;
            Messages = messages ?? new();
        }
    }
}