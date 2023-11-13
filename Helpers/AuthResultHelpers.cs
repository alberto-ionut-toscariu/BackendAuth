using BackendAuth.Models;

namespace BackendAuth.Helpers
{
    public class AuthResultHelper
    {
        public static AuthResult CreateSuccessResponse(string message)
        {
            return new AuthResult
            {
                Success = true,
                Status = 200,
                Messages = new List<string> { message }

            };
        }
        public static AuthResult CreateSuccessResponse(string token, string message)
        {
            return new AuthResult
            {
                Success = true,
                Status = 200,
                Token = token,
                Messages = new List<string> { message }

            };
        }

        public static AuthResult CreateErrorResponse(string errorMessage, int statusCode)
        {
            return new AuthResult
            {
                Success = false,
                Messages = new List<string> { errorMessage },
                Status = statusCode
            };
        }
    }
}