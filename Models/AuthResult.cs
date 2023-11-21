namespace BackendAuth.Models
{
    public class AuthResult
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public bool Success { get; set; }
        public int Status { get; set; }
        public List<string> Messages { get; set; }
    }
}