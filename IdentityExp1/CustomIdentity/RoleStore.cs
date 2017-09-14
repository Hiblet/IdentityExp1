using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Threading;
using Microsoft.Extensions.Options; // IOptions

namespace NZ01
{
    public class RoleStore : IRoleStore<ApplicationRole>
    {
        public readonly ILogger _logger;
        public readonly string _connStr;
        public readonly CustomDynamicOptions _options;

        public readonly string _notImpl = "Function intentionally not implemented; ";
        public readonly string _useAppRole = "ApplicationRole object should provide access.";


        public RoleStore(ILogger<RoleStore> logger, IOptions<CustomDynamicOptions> optionsContainer)
        {
            _logger = logger;
            _options = optionsContainer.Value;
            _connStr = _options.ConnStr;
        }

        public Task<IdentityResult> CreateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            try
            {
                using (var rolesDAL = new AspNetRolesDAL(_connStr))
                {
                    rolesDAL.Insert(role);
                }
            }
            catch (Exception ex)
            {
                List<IdentityError> idErrors = new List<IdentityError>();
                IdentityError idError = new IdentityError { Description = ex.Message };
                idErrors.Add(idError);

                return Task.FromResult(IdentityResult.Failed(idErrors.ToArray()));
            }

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            try
            {
                using (var rolesDAL = new AspNetRolesDAL(_connStr))
                {
                    rolesDAL.Update(role);
                }
            }
            catch (Exception ex)
            {
                List<IdentityError> idErrors = new List<IdentityError>();
                IdentityError idError = new IdentityError { Description = ex.Message };
                idErrors.Add(idError);

                return Task.FromResult(IdentityResult.Failed(idErrors.ToArray()));
            }

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<ApplicationRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            string prefix = nameof(FindByIdAsync) + Constants.FNSUFFIX;

            ApplicationRole appRole = null;

            if (!string.IsNullOrWhiteSpace(roleId))
            {
                try
                {
                    using (var rolesDAL = new AspNetRolesDAL(_connStr))
                    {
                        appRole = rolesDAL.SelectByRoleId(roleId);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
                }
            }

            return Task.FromResult(appRole);
        }


        public Task<ApplicationRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            string prefix = nameof(FindByNameAsync) + Constants.FNSUFFIX;

            ApplicationRole appRole = null;

            if (!string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                try
                {
                    using (var rolesDAL = new AspNetRolesDAL(_connStr))
                    {
                        appRole = rolesDAL.SelectByRoleName(normalizedRoleName);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
                }
            }

            return Task.FromResult(appRole);
        }

        public void Dispose() { }

        public Task<IdentityResult> DeleteAsync(ApplicationRole role, CancellationToken cancellationToken) { throw new NotImplementedException(_notImpl); }
        public Task<string> GetRoleIdAsync(ApplicationRole role, CancellationToken cancellationToken) { return Task.FromResult(role.RoleId); }
        public Task<string> GetRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken) { return Task.FromResult(role.RoleName); }
        public Task<string> GetNormalizedRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken) { return Task.FromResult(role.RoleNameNormalized); }
        public Task SetRoleNameAsync(ApplicationRole role, string roleName, CancellationToken cancellationToken) { return Task.CompletedTask; }
        public Task SetNormalizedRoleNameAsync(ApplicationRole role, string normalizedRoleName, CancellationToken cancellationToken) { return Task.CompletedTask; }
    }
}
