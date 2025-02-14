using JwtAuthProject.Models;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthProject.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
