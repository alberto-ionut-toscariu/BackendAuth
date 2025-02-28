using BackendAuth.Models;
using System.Net;

namespace BackendAuth.Helpers
{
    public static class AuthResultHelper
    {
        public static AuthResult CreateSuccessResponse(string message)
            => new(success: true, status: HttpStatusCode.OK, messages: new List<string> { message });

        public static AuthResult CreateSuccessResponse(List<string> messages)
            => new(success: true, status: HttpStatusCode.OK, messages: messages);

        public static AuthResult CreateSuccessResponseWithToken(string token, string refreshToken, string message)
            => new(success: true, status: HttpStatusCode.OK, messages: new List<string> { message }, token: token, refreshToken: refreshToken);

        public static AuthResult CreateSuccessResponseWithToken(string token, string refreshToken, List<string> messages)
            => new(success: true, status: HttpStatusCode.OK, messages: messages, token: token, refreshToken: refreshToken);

        public static AuthResult CreateErrorResponse(string errorMessage, HttpStatusCode statusCode = HttpStatusCode.InternalServerError)
            => new(success: false, status: statusCode, messages: new List<string> { errorMessage });

        public static AuthResult CreateErrorResponse(List<string> errorMessages, HttpStatusCode statusCode = HttpStatusCode.InternalServerError)
            => new(success: false, status: statusCode, messages: errorMessages);
    }
}