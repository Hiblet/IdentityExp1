using System;
using System.Collections.Generic;
using System.Text;
using Moq;
using IdentityExp1.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Builder;
using System.Threading.Tasks;
using System.Threading;

using NZ01;

namespace IdentityExp1Test
{
    public class FakeUserManager : UserManager<ApplicationUser>
    {
        public FakeUserManager() : base(
            new Mock<IUserStore<ApplicationUser>>().Object,
            new Mock<IOptions<IdentityOptions>>().Object,
            new Mock<IPasswordHasher<ApplicationUser>>().Object,
            new IUserValidator<ApplicationUser>[0],
            new IPasswordValidator<ApplicationUser>[0],
            new Mock<ILookupNormalizer>().Object,
            new Mock<IdentityErrorDescriber>().Object,
            new Mock<IServiceProvider>().Object,
            new Mock<ILogger<UserManager<ApplicationUser>>>().Object)
        { }

        public override Task<IdentityResult> CreateAsync(ApplicationUser user, string password)
        {
            return Task.FromResult(IdentityResult.Success);
        }


        public override Task<ApplicationUser> FindByNameAsync(string username)
        {
           
            HashSet<string> roles = new HashSet<string>();
            //roles.Add("User");
            //var user = new ApplicationUser { UserId = username + "_GUID", UserName = username, Roles = roles };
            var user = new ApplicationUser { UserId = username + "_GUID", UserName = username };
            return Task.FromResult(user);
        }

        public override Task<bool> CheckPasswordAsync(ApplicationUser user, string password)
        {
            return Task.FromResult(true);
        }

    }
}

