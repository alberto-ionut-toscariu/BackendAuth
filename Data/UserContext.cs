using BackendAuth.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace BackendAuth.Data
{
    public class UserContext : IdentityDbContext
    {
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public UserContext(DbContextOptions<UserContext> options) : base(options)
        { }
    }
}