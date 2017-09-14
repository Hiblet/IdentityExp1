using System.Security.Claims;
using System.Collections.Generic;
using System; // DateTimeOffset

namespace NZ01
{

    public class ApplicationUser : ClaimsIdentity
    {
        public string UserName { get; set; }
        public string UserId { get; set; }
        public int AccessFailedCount { get; set; } 
        public string ConcurrencyStamp { get; set; } 
        public string Email { get; set; }
        public bool EmailConfirmed { get; set; }
        public string EmailNormalized => Email?.ToUpper();
        public string UserNameNormalized => UserName?.ToUpper();
        public string PasswordHash { get; set; }
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public string SecurityStamp { get; set; }
        public bool Enabled { get; set; } = true;
        public bool LockoutEnabled { get; set; }
        public DateTime LockoutEnd { get; set; }
    }

    public class ExampleApplicationUser : ClaimsIdentity
    {
        public string UserName { get; set; }
        public string UserId { get; set; }
        public int AccessFailedCount { get; set; }
        public string ConcurrencyStamp { get; set; }
        public string Email { get; set; }
        public bool EmailConfirmed { get; set; }
        public string EmailNormalized => Email?.ToUpper();
        public string UserNameNormalized => UserName?.ToUpper();
        public string PasswordHash { get; set; }
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public string SecurityStamp { get; set; }
        public HashSet<string> Roles { get; set; } = new HashSet<string>();
        public bool Enabled { get; set; } = true;
        public bool LockoutEnabled { get; set; }
        public DateTime LockoutEnd { get; set; }
    }


    // Previous version for reference only...
    /*
    public class ApplicationUser : ClaimsIdentity
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string UserNameNormalized => UserName?.ToUpper();
        public string Email { get; set; }
        public string EmailNormalized => Email?.ToUpper();
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public string PasswordHash { get; set; }
        public bool TwoFactorEnabled { get; set; }
    }
    */
}
