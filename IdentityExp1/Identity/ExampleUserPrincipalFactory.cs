﻿using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

using IdentityExp1.Models;
using NZ01;

namespace NZ01
{
    public class ExampleUserPrincipalFactory : IUserClaimsPrincipalFactory<ExampleApplicationUser>
    {
        private readonly IdentityOptions _options;

        public ExampleUserPrincipalFactory(IOptions<IdentityOptions> optionsAccessor)
        {
            _options = optionsAccessor?.Value ?? new IdentityOptions();
        }

        public Task<ClaimsPrincipal> CreateAsync(ExampleApplicationUser user)
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
