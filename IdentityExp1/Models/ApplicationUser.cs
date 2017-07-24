using System.Security.Claims;
using System.Collections.Generic;

namespace IdentityExp1.Models
{
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
        public HashSet<string> Roles { get; set; } = new HashSet<string>();
        public bool Enabled { get; set; } = true;
    }

}
