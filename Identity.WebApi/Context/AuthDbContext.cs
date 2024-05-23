using Identity.WebApi.Module;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query.Internal;
using System.Xml;

namespace Identity.WebApi.Context
{
    public class AuthDbContext : IdentityDbContext
    {
        public AuthDbContext(DbContextOptions options) : base(options)
        {

        }
        public DbSet<Users> Users { get; set; }
        public DbSet<FriendLists> FriendLists { get; set; }
        public DbSet<ExtendedIdentityUser> ExtendedIdentityUser { get; set; }

    }
}
