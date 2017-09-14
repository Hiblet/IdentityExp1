using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity; // IUserStore etc
using System.Threading; // CancellationToken
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options; // IOptions


namespace NZ01
{
    public class UserStore : 
        IUserStore<ApplicationUser>, 
        IUserEmailStore<ApplicationUser>, 
        IUserPasswordStore<ApplicationUser>,
        IUserPhoneNumberStore<ApplicationUser>,        
        IUserTwoFactorStore<ApplicationUser>,
        IUserRoleStore<ApplicationUser>,
        IUserTokenStore<ApplicationJwtRefreshToken>,
        IQueryableUserStore<ApplicationUser>
    {
        public readonly ILogger _logger;
        public readonly string _connStr;
        public readonly CustomDynamicOptions _options;

        public readonly string _notImpl = "Function intentionally not implemented; ";
        public readonly string _useAppUser = "ApplicationUser object should provide access.";



        public UserStore(ILogger<UserStore> logger, IOptions<CustomDynamicOptions> optionsContainer)
        {
            _logger = logger;
            _options = optionsContainer.Value;
            _connStr = _options.ConnStr;
        }


        #region USERS

        public IQueryable<ApplicationUser> Users
        {
            get
            {
                //return _users.AsQueryable<ApplicationUser>();

                using (var usersDAL = new AspNetUsersDAL(_connStr))
                {
                    var users = usersDAL.SelectAll();
                }
                return Users.AsQueryable<ApplicationUser>();
            }
        }


        public Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            try
            {
                using (var usersDAL = new AspNetUsersDAL(_connStr))
                {
                    usersDAL.Insert(user);
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

        public Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            try
            {
                using (var usersDAL = new AspNetUsersDAL(_connStr))
                {
                    usersDAL.Update(user);
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

        public Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            string prefix = nameof(FindByIdAsync) + Constants.FNSUFFIX;

            ApplicationUser appUser = null;

            if (!string.IsNullOrWhiteSpace(userId))
            {
                try
                {
                    using (var usersDAL = new AspNetUsersDAL(_connStr))
                    {
                        appUser = usersDAL.SelectByUserId(userId);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
                }
            }

            return Task.FromResult(appUser);
        }

        public Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            string prefix = nameof(FindByNameAsync) + Constants.FNSUFFIX;

            ApplicationUser appUser = null;

            if (!string.IsNullOrWhiteSpace(normalizedUserName))
            {
                try
                {
                    using (var usersDAL = new AspNetUsersDAL(_connStr))
                    {
                        appUser = usersDAL.SelectByUserName(normalizedUserName);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
                }
            }

            return Task.FromResult(appUser);
        }

        public void Dispose() { }

        public Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
        { throw new NotImplementedException(_notImpl + "Deleting a user should be achieved by setting the enabled flag false."); }

        public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken) { return Task.FromResult(user.UserId); }
        public Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken) { return Task.FromResult(user.UserName); }
        public Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken) { return Task.FromResult(user.UserNameNormalized); }
        public Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken) { return Task.CompletedTask; }
        public Task SetNormalizedUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken) { return Task.CompletedTask; }

        #endregion USERS



        #region ROLES

        public Task AddToRoleAsync(ApplicationUser user, string roleName, CancellationToken cToken)
        {
            string prefix = nameof(AddToRoleAsync) + Constants.FNSUFFIX;
            
            ApplicationRole appRole = null;

            try
            {
                using (var rolesDAL = new AspNetRolesDAL(_connStr)) { appRole = rolesDAL.SelectByRoleName(roleName.ToUpper()); }

                if (appRole != null)
                    using (var userRolesDAL = new AspNetUserRolesDAL(_connStr)) { userRolesDAL.Insert(user.UserId, appRole.RoleId); }
            }
            catch (Exception ex)
            {
                _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
            }

            return Task.CompletedTask;
        }


        public Task RemoveFromRoleAsync(ApplicationUser user, string roleName, CancellationToken cToken)
        {
            string prefix = nameof(RemoveFromRoleAsync) + Constants.FNSUFFIX;

            ApplicationRole appRole = null;

            try
            {
                using (var rolesDAL = new AspNetRolesDAL(_connStr)) { appRole = rolesDAL.SelectByRoleName(roleName.ToUpper()); }

                if (appRole != null)
                    using (var userRolesDAL = new AspNetUserRolesDAL(_connStr)) { userRolesDAL.Delete(user.UserId, appRole.RoleId); }
            }
            catch (Exception ex)
            {
                _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
            }

            return Task.CompletedTask;
        }

        public Task<IList<string>> GetRolesAsync(ApplicationUser user, CancellationToken cToken)
        {
            string prefix = nameof(GetRolesAsync) + Constants.FNSUFFIX;

            IList<string> roles = new List<string>();

            try
            {
                IEnumerable<string> roleIDs = null;
                using (var userRolesDAL = new AspNetUserRolesDAL(_connStr)) { roleIDs = userRolesDAL.SelectRolesForUser(user.UserId) ; }

                if (roleIDs.Any())
                {
                    using (var rolesDAL = new AspNetRolesDAL(_connStr)) { roles = rolesDAL.SelectRoleNamesByRoleId(roleIDs).ToList(); }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
            }

            return Task.FromResult(roles);
        }

        public Task<bool> IsInRoleAsync(ApplicationUser user, string roleName, CancellationToken cToken)
        {
            string prefix = nameof(IsInRoleAsync) + Constants.FNSUFFIX;

            bool result = false;

            try
            {
                // Get the role to get the roleID
                ApplicationRole appRole;
                using (var rolesDAL = new AspNetRolesDAL(_connStr)) { appRole = rolesDAL.SelectByRoleName(roleName.ToUpper()); }

                if (appRole != null)
                {
                    // Get the roleIDs for the user
                    IEnumerable<string> roleIDsForUser;
                    using (var userRolesDAL = new AspNetUserRolesDAL(_connStr)) { roleIDsForUser = userRolesDAL.SelectRolesForUser(user.UserId); }

                    foreach (string roleID in roleIDsForUser)
                    {
                        if (string.Equals(roleID, appRole.RoleId, StringComparison.OrdinalIgnoreCase))
                        {
                            result = true;
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
            }

            return Task.FromResult(result);
        }

        public Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cToken)
        {
            string prefix = nameof(GetUsersInRoleAsync) + Constants.FNSUFFIX;

            IList<ApplicationUser> users = new List<ApplicationUser>();

            try
            {
                // Get the roleID from the roleName
                ApplicationRole appRole;
                using (var rolesDAL = new AspNetRolesDAL(_connStr)) { appRole = rolesDAL.SelectByRoleName(roleName.ToUpper()); }

                if (appRole != null)
                {
                    // Get the userIDs that have this roleID
                    IEnumerable<string> userIDsWithRoleID;
                    using (var userRolesDAL = new AspNetUserRolesDAL(_connStr)) { userIDsWithRoleID = userRolesDAL.SelectUsersInRole(appRole.RoleId); }

                    if (userIDsWithRoleID.Any())
                    {
                        // Get the users with these userIDs
                        using (var usersDAL = new AspNetUsersDAL(_connStr)) { users = usersDAL.SelectByUserIDs(userIDsWithRoleID).ToList(); }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
            }

            return Task.FromResult(users);
        }

        #endregion ROLES



        #region EMAIL

        public Task SetEmailAsync(ApplicationUser user, string email, CancellationToken cancellationToken)
        {
            string prefix = nameof(SetEmailAsync) + Constants.FNSUFFIX;

            user.Email = email;
            try { using (var usersDAL = new AspNetUsersDAL(_connStr)) { usersDAL.Update(user); } }
            catch (Exception ex) { _logger.LogError(prefix + $"Exception:[{ex.ToString()}]"); }

            return Task.CompletedTask;
        }

        public Task<string> GetEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            string prefix = nameof(SetEmailConfirmedAsync) + Constants.FNSUFFIX;

            user.EmailConfirmed = confirmed;
            try { using (var usersDAL = new AspNetUsersDAL(_connStr)) { usersDAL.Update(user); } }
            catch (Exception ex) { _logger.LogError(prefix + $"Exception:[{ex.ToString()}]"); }

            return Task.CompletedTask;
        }

        public Task<ApplicationUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            string prefix = nameof(FindByEmailAsync) + Constants.FNSUFFIX;

            ApplicationUser appUser = null;

            if (!string.IsNullOrWhiteSpace(normalizedEmail))
            {
                try
                {
                    using (var usersDAL = new AspNetUsersDAL(_connStr))
                    {
                        appUser = usersDAL.SelectByEmail(normalizedEmail);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
                }
            }

            return Task.FromResult(appUser);
        }

        public Task<string> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.EmailNormalized);
        }

        public Task SetNormalizedEmailAsync(ApplicationUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        #endregion EMAIL


        #region PASSWORD

        public Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            string prefix = nameof(SetPasswordHashAsync) + Constants.FNSUFFIX;

            user.PasswordHash = passwordHash;
            try { using (var usersDAL = new AspNetUsersDAL(_connStr)) { usersDAL.Update(user); } }
            catch (Exception ex) { _logger.LogError(prefix + $"Exception:[{ex.ToString()}]"); }

            return Task.CompletedTask;
        }

        #endregion PASSWORD



        #region PHONENUMBER

        public Task<string> GetPhoneNumberAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumber);
        }

        public Task SetPhoneNumberAsync(ApplicationUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            string prefix = nameof(SetPhoneNumberAsync) + Constants.FNSUFFIX;

            user.PhoneNumber = phoneNumber;
            try { using (var usersDAL = new AspNetUsersDAL(_connStr)) { usersDAL.Update(user); } }
            catch (Exception ex) { _logger.LogError(prefix + $"Exception:[{ex.ToString()}]"); }

            return Task.CompletedTask;
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            string prefix = nameof(SetPhoneNumberConfirmedAsync) + Constants.FNSUFFIX;

            user.PhoneNumberConfirmed = confirmed;
            try { using (var usersDAL = new AspNetUsersDAL(_connStr)) { usersDAL.Update(user); } }
            catch (Exception ex) { _logger.LogError(prefix + $"Exception:[{ex.ToString()}]"); }

            return Task.CompletedTask;
        }

        #endregion PHONENUMBER



        #region TWOFACTOR

        public Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            string prefix = nameof(SetTwoFactorEnabledAsync) + Constants.FNSUFFIX;

            user.TwoFactorEnabled = enabled;
            try { using (var usersDAL = new AspNetUsersDAL(_connStr)) { usersDAL.Update(user); } }
            catch (Exception ex) { _logger.LogError(prefix + $"Exception:[{ex.ToString()}]"); }

            return Task.CompletedTask;
        }

        public Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.TwoFactorEnabled);
        }

        #endregion TWOFACTOR



        #region TOKENS

        public Task InsertTokenAsync(ApplicationJwtRefreshToken token, CancellationToken cancellationToken)
        {
            string prefix = nameof(InsertTokenAsync) + Constants.FNSUFFIX;

            try { using (var tokensDAL = new AspNetTokensDAL(_connStr)) { tokensDAL.Insert(token); } }
            catch (Exception ex) { _logger.LogError(prefix + $"Exception:[{ex.ToString()}]"); }

            return Task.CompletedTask;
        }

        public Task<ApplicationJwtRefreshToken> ExtractTokenAsync(string guid, CancellationToken cancellationToken)
        {
            string prefix = nameof(ExtractTokenAsync) + Constants.FNSUFFIX;

            ApplicationJwtRefreshToken token = null;
            try
            {
                using (var tokensDAL = new AspNetTokensDAL(_connStr))
                {
                    token = tokensDAL.SelectByGuid(guid);
                    if (token != null)                    
                        tokensDAL.Delete(guid);                    
                }
            }
            catch (Exception ex) { _logger.LogError(prefix + $"Exception:[{ex.ToString()}]"); }

            return Task.FromResult(token);
        }

        #endregion TOKENS

    }
}