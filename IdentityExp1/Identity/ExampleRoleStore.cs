using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

using IdentityExp1.Models;
using NZ01;

namespace NZ01
{
    public class ExampleRoleStore : IRoleStore<ExampleApplicationRole>
    {
        private readonly List<ExampleApplicationRole> _roles;

        public ExampleRoleStore()
        {
            _roles = new List<ExampleApplicationRole>();
        }

        public Task<IdentityResult> CreateAsync(ExampleApplicationRole role, CancellationToken cancellationToken)
        {
            _roles.Add(role);

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateAsync(ExampleApplicationRole role, CancellationToken cancellationToken)
        {
            var match = _roles.FirstOrDefault(r => r.RoleId == role.RoleId);
            if (match != null)
            {
                match.RoleName = role.RoleName;

                return Task.FromResult(IdentityResult.Success);
            }
            else
            {
                return Task.FromResult(IdentityResult.Failed());
            }
        }

        public Task<IdentityResult> DeleteAsync(ExampleApplicationRole role, CancellationToken cancellationToken)
        {
            var match = _roles.FirstOrDefault(r => r.RoleId == role.RoleId);
            if (match != null)
            {
                _roles.Remove(match);

                return Task.FromResult(IdentityResult.Success);
            }
            else
            {
                return Task.FromResult(IdentityResult.Failed());
            }
        }

        public Task<ExampleApplicationRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            var role = _roles.FirstOrDefault(r => r.RoleId == roleId);

            return Task.FromResult(role);
        }

        public Task<ExampleApplicationRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            var role = _roles.FirstOrDefault(r => String.Equals(r.RoleNameNormalized, normalizedRoleName, StringComparison.OrdinalIgnoreCase));

            return Task.FromResult(role);
        }

        public Task<string> GetRoleIdAsync(ExampleApplicationRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.RoleId);
        }

        public Task<string> GetRoleNameAsync(ExampleApplicationRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.RoleName);
        }

        public Task<string> GetNormalizedRoleNameAsync(ExampleApplicationRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.RoleNameNormalized);
        }

        public Task SetRoleNameAsync(ExampleApplicationRole role, string roleName, CancellationToken cancellationToken)
        {
            role.RoleName = roleName;

            return Task.FromResult(true);
        }

        public Task SetNormalizedRoleNameAsync(ExampleApplicationRole role, string normalizedName, CancellationToken cancellationToken)
        {
            // Do nothing. In this simple example, the normalized name is generated from the role name.
            
            return Task.FromResult(true);
        }

        public void Dispose() { }
    }
}
