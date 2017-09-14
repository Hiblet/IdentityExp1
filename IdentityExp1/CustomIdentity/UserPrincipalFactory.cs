using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder; // IdentityOptions
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims; // ClaimsPrincipal

namespace NZ01
{
    public class UserPrincipalFactory : IUserClaimsPrincipalFactory<ApplicationUser>
    {
        private readonly IdentityOptions _options;

        public UserPrincipalFactory(IOptions<IdentityOptions> optionsAccessor)
        {
            _options = optionsAccessor?.Value ?? new IdentityOptions();
        }

        public Task<ClaimsPrincipal> CreateAsync(ApplicationUser user)
        {
            var identity = new ClaimsIdentity(
                _options.Cookies.ApplicationCookieAuthenticationScheme,
                _options.ClaimsIdentity.UserNameClaimType,
                _options.ClaimsIdentity.RoleClaimType);

            identity.AddClaim(new Claim(_options.ClaimsIdentity.UserIdClaimType, user.UserId));
            identity.AddClaim(new Claim(_options.ClaimsIdentity.UserNameClaimType, user.UserName));

            var principal = new ClaimsPrincipal(identity);

            return Task.FromResult(principal);
        }
    }
}
