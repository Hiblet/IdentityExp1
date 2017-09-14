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

    public class ExampleUserStore : IUserStore<ExampleApplicationUser>,
                                    IUserEmailStore<ExampleApplicationUser>,
                                    IUserPasswordStore<ExampleApplicationUser>,
                                    IUserLoginStore<ExampleApplicationUser>,
                                    IUserPhoneNumberStore<ExampleApplicationUser>,
                                    IUserTwoFactorStore<ExampleApplicationUser>,
                                    IUserRoleStore<ExampleApplicationUser>,
                                    IQueryableUserStore<ExampleApplicationUser>,
                                    IUserTokenStore<ApplicationJwtRefreshToken>
    {
        private static readonly List<ExampleApplicationUser> _users = new List<ExampleApplicationUser>();
        private static readonly ExampleTokenStore _tokens = new ExampleTokenStore();
        
        public IQueryable<ExampleApplicationUser> Users
        {
            get
            {                
                return _users.AsQueryable<ExampleApplicationUser>(); 
            }
        }

        public Task<IdentityResult> CreateAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            user.UserId = Guid.NewGuid().ToString();

            _users.Add(user);

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            var match = _users.FirstOrDefault(u => u.UserId == user.UserId);
            if (match != null)
            {
                match.UserName = user.UserName;
                match.Email = user.Email;
                match.PhoneNumber = user.PhoneNumber;
                match.TwoFactorEnabled = user.TwoFactorEnabled;
                match.PasswordHash = user.PasswordHash;

                return Task.FromResult(IdentityResult.Success);
            }
            else
            {
                return Task.FromResult(IdentityResult.Failed());
            }
        }

        public Task<IdentityResult> DeleteAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            var match = _users.FirstOrDefault(u => u.UserId == user.UserId);
            if (match != null)
            {
                _users.Remove(match);

                return Task.FromResult(IdentityResult.Success);
            }
            else
            {
                return Task.FromResult(IdentityResult.Failed());
            }
        }

        public Task<ExampleApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var user = _users.FirstOrDefault(u => u.UserId == userId);

            return Task.FromResult(user);
        }

        public Task<ExampleApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            var user = _users.FirstOrDefault(u => String.Equals(u.UserNameNormalized, normalizedUserName, StringComparison.OrdinalIgnoreCase));

            return Task.FromResult(user);
        }

        public Task<string> GetUserIdAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserId);
        }

        public Task<string> GetUserNameAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserName);
        }

        public Task<string> GetNormalizedUserNameAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserNameNormalized);
        }

        public Task SetEmailAsync(ExampleApplicationUser user, string email, CancellationToken cancellationToken)
        {
            user.Email = email;

            return Task.CompletedTask;
        }

        public Task<string> GetEmailAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(true);
        }

        public Task SetEmailConfirmedAsync(ExampleApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<ExampleApplicationUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            var user = _users.FirstOrDefault(u => String.Equals(u.EmailNormalized, normalizedEmail, StringComparison.OrdinalIgnoreCase));

            return Task.FromResult(user);
        }

        public Task<string> GetNormalizedEmailAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.EmailNormalized);
        }

        public Task SetNormalizedEmailAsync(ExampleApplicationUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            // Do nothing. In this simple example, the normalized email is generated from the email.

            return Task.CompletedTask;
        }

        public Task<string> GetPasswordHashAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetUserNameAsync(ExampleApplicationUser user, string userName, CancellationToken cancellationToken)
        {
            user.UserName = userName;

            return Task.FromResult(true);
        }

        public Task SetNormalizedUserNameAsync(ExampleApplicationUser user, string normalizedName, CancellationToken cancellationToken)
        {
            // Do nothing. In this simple example, the normalized user name is generated from the user name.

            return Task.FromResult(true);
        }

        public Task SetPasswordHashAsync(ExampleApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;

            return Task.FromResult(true);
        }

        public Task<string> GetPhoneNumberAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumber);
        }

        public Task SetPhoneNumberAsync(ExampleApplicationUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            user.PhoneNumber = phoneNumber;

            return Task.FromResult(true);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(ExampleApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.PhoneNumberConfirmed = confirmed;

            return Task.FromResult(true);
        }

        public Task SetTwoFactorEnabledAsync(ExampleApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            user.TwoFactorEnabled = enabled;

            return Task.FromResult(true);
        }

        public Task<bool> GetTwoFactorEnabledAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            // Just returning an empty list because I don't feel like implementing this. You should get the idea though...
            IList<UserLoginInfo> logins = new List<UserLoginInfo>();
            return Task.FromResult(logins);
        }

        public Task<ExampleApplicationUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task AddLoginAsync(ExampleApplicationUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task RemoveLoginAsync(ExampleApplicationUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        // Add a record in the AspNetUserRoles table
        public Task AddToRoleAsync(ExampleApplicationUser user, string roleName, CancellationToken cToken)
        {
            user.Roles.Add(roleName);
            return Task.CompletedTask;
        }

        public Task RemoveFromRoleAsync(ExampleApplicationUser user, string roleName, CancellationToken cToken)
        {
            user.Roles.Remove(roleName);
            return Task.CompletedTask;
        }

        public Task<IList<string>> GetRolesAsync(ExampleApplicationUser user, CancellationToken cToken)
        {            
            IList<string> roles = user.Roles.ToList();
            return Task.FromResult(roles);
        }

        public Task<bool> IsInRoleAsync(ExampleApplicationUser user, string roleName, CancellationToken cToken)
        {
            foreach (string role in user.Roles)
            {
               if (string.Equals(role, roleName, StringComparison.OrdinalIgnoreCase))
                   return Task.FromResult(true);
            }

            return Task.FromResult(false);
        }

        public Task<IList<ExampleApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cToken)
        {
            
            IList<ExampleApplicationUser> usersInRole = new List<ExampleApplicationUser>();
            foreach (ExampleApplicationUser user in _users)
            {
                foreach (string role in user.Roles)
                {
                    if (string.Equals(role, roleName, StringComparison.OrdinalIgnoreCase))
                    {
                        usersInRole.Add(user);
                        break;
                    }
                }
            }
            return Task.FromResult(usersInRole);
        }

        public Task InsertTokenAsync(ApplicationJwtRefreshToken token, CancellationToken cancellationToken)
        {
            string prefix = nameof(InsertTokenAsync) + Constants.FNSUFFIX;

            _tokens.CreateAsync(token, cancellationToken);

            return Task.CompletedTask;
        }

        public Task<ApplicationJwtRefreshToken> ExtractTokenAsync(string guid, CancellationToken cancellationToken)
        {
            string prefix = nameof(ExtractTokenAsync) + Constants.FNSUFFIX;

            ApplicationJwtRefreshToken token = _tokens.FindByGuidAsync(guid, cancellationToken).Result;
            if (token != null) _tokens.DeleteAsync(guid, cancellationToken);

            return Task.FromResult(token);
        }

        public Task AddTokenAsync(ExampleApplicationUser user, ApplicationJwtRefreshToken token, CancellationToken cToken)
        {
            return _tokens.CreateAsync(token, cToken);
        }

        public Task RemoveTokenAsync(string guid, CancellationToken cToken)
        {
            return _tokens.DeleteAsync(guid, cToken);
        }

        public Task<ApplicationJwtRefreshToken> GetTokenAsync(string guid, CancellationToken cToken)
        {
            return _tokens.FindByGuidAsync(guid, cToken);
        }

        public void Dispose() { }
    }


    /*
    public class ExampleUserStore : IUserStore<ExampleApplicationUser>,
                                    IUserEmailStore<ExampleApplicationUser>,
                                    IUserPasswordStore<ExampleApplicationUser>,
                                    IUserLoginStore<ExampleApplicationUser>,
                                    IUserPhoneNumberStore<ExampleApplicationUser>,
                                    IUserTwoFactorStore<ExampleApplicationUser>
    {
        private static readonly List<ExampleApplicationUser> _users = new List<ExampleApplicationUser>();

        public Task<IdentityResult> CreateAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            user.UserId = Guid.NewGuid().ToString();

            _users.Add(user);

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            var match = _users.FirstOrDefault(u => u.UserId == user.UserId);
            if (match != null)
            {
                match.UserName = user.UserName;
                match.Email = user.Email;
                match.PhoneNumber = user.PhoneNumber;
                match.TwoFactorEnabled = user.TwoFactorEnabled;
                match.PasswordHash = user.PasswordHash;

                return Task.FromResult(IdentityResult.Success);
            }
            else
            {
                return Task.FromResult(IdentityResult.Failed());
            }
        }

        public Task<IdentityResult> DeleteAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            var match = _users.FirstOrDefault(u => u.UserId == user.UserId);
            if (match != null)
            {
                _users.Remove(match);

                return Task.FromResult(IdentityResult.Success);
            }
            else
            {
                return Task.FromResult(IdentityResult.Failed());
            }
        }

        public Task<ExampleApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var user = _users.FirstOrDefault(u => u.UserId == userId);

            return Task.FromResult(user);
        }

        public Task<ExampleApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            var user = _users.FirstOrDefault(u => String.Equals(u.UserNameNormalized, normalizedUserName, StringComparison.OrdinalIgnoreCase));

            return Task.FromResult(user);
        }

        public Task<string> GetUserIdAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserId);
        }

        public Task<string> GetUserNameAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserName);
        }

        public Task<string> GetNormalizedUserNameAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserNameNormalized);
        }

        public Task SetEmailAsync(ExampleApplicationUser user, string email, CancellationToken cancellationToken)
        {
            user.Email = email;

            return Task.CompletedTask;
        }

        public Task<string> GetEmailAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(true);
        }

        public Task SetEmailConfirmedAsync(ExampleApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<ExampleApplicationUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            var user = _users.FirstOrDefault(u => String.Equals(u.EmailNormalized, normalizedEmail, StringComparison.OrdinalIgnoreCase));

            return Task.FromResult(user);
        }

        public Task<string> GetNormalizedEmailAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.EmailNormalized);
        }

        public Task SetNormalizedEmailAsync(ExampleApplicationUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            // Do nothing. In this simple example, the normalized email is generated from the email.

            return Task.CompletedTask;
        }

        public Task<string> GetPasswordHashAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetUserNameAsync(ExampleApplicationUser user, string userName, CancellationToken cancellationToken)
        {
            user.UserName = userName;

            return Task.FromResult(true);
        }

        public Task SetNormalizedUserNameAsync(ExampleApplicationUser user, string normalizedName, CancellationToken cancellationToken)
        {
            // Do nothing. In this simple example, the normalized user name is generated from the user name.

            return Task.FromResult(true);
        }

        public Task SetPasswordHashAsync(ExampleApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;

            return Task.FromResult(true);
        }

        public Task<string> GetPhoneNumberAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumber);
        }

        public Task SetPhoneNumberAsync(ExampleApplicationUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            user.PhoneNumber = phoneNumber;

            return Task.FromResult(true);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(ExampleApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.PhoneNumberConfirmed = confirmed;

            return Task.FromResult(true);
        }

        public Task SetTwoFactorEnabledAsync(ExampleApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            user.TwoFactorEnabled = enabled;

            return Task.FromResult(true);
        }

        public Task<bool> GetTwoFactorEnabledAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(ExampleApplicationUser user, CancellationToken cancellationToken)
        {
            // Just returning an empty list because I don't feel like implementing this. You should get the idea though...
            IList<UserLoginInfo> logins = new List<UserLoginInfo>();
            return Task.FromResult(logins);
        }

        public Task<ExampleApplicationUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task AddLoginAsync(ExampleApplicationUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task RemoveLoginAsync(ExampleApplicationUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public void Dispose() { }
    }
    */
}
