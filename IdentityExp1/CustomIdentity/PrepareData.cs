using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration; // IConfigurationRoot
using Microsoft.AspNetCore.Identity;

namespace NZ01
{
    public class PrepareData
    {
        public static ILogger _logger;
        public static UserManager<ApplicationUser> _userManager;
        public static RoleManager<ApplicationRole> _roleManager;

        public static void Init(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, ILogger logger)
        {
            _logger = logger;
            _userManager = userManager;
            _roleManager = roleManager;

            createRoleIfNotExistent("ADMIN");
            createRoleIfNotExistent("USER");

            createUserIfNotExistent("Admin", "test123", new List<string> { "ADMIN", "USER" });
            createUserIfNotExistent("Alice", "test123", new List<string> { "USER" });
            createUserIfNotExistent("Bob", "test123", new List<string>());
            createUserIfNotExistent("Charlie", "test123", new List<string> { "ADMIN" });
        }

        private static void createRoleIfNotExistent(string roleName)
        {
            string prefix = nameof(createRoleIfNotExistent) + Constants.FNSUFFIX;

            ApplicationRole appRoleExistent = _roleManager.FindByNameAsync(roleName).Result;

            if (appRoleExistent != null)
            {
                _logger.LogDebug(prefix + $"Positive result; Role [{roleName}] exists.  New role will not be created.");
                return;
            }

            // Role does not exist

            ApplicationRole appRole = new ApplicationRole
            {
                RoleName = roleName,
                RoleId = Guid.NewGuid().ToString(Constants.GUID_DB),
                ConcurrencyStamp = Guid.NewGuid().ToString(Constants.GUID_DB)
            };

            IdentityResult idresult = _roleManager.CreateAsync(appRole).Result;

            if (idresult.Succeeded)
            {
                _logger.LogDebug(prefix + $"Positive result; Role [{roleName}] did not exist, and was created.");
                return;
            }
            else
            {
                string msg = $"Failed to create role [{roleName}]";
                _logger.LogError(prefix + msg);
                throw new Exception(msg);
            }
        }

        private static void createUserIfNotExistent(string username, string password, IEnumerable<string> roles)
        {
            string prefix = nameof(createUserIfNotExistent) + Constants.FNSUFFIX;

            ApplicationUser appUserExistent = _userManager.FindByNameAsync(username).Result;

            if (appUserExistent != null)
            {
                _logger.LogDebug(prefix + $"Positive result; User [{username}] exists.  New user will not be created.");
                return;
            }

            ApplicationUser appUser = new ApplicationUser
            {
                UserName = username,
                UserId = Guid.NewGuid().ToString(Constants.GUID_DB),
                Enabled = true,
                SecurityStamp = Guid.NewGuid().ToString(Constants.GUID_DB),
                ConcurrencyStamp = Guid.NewGuid().ToString(Constants.GUID_DB)
            };

            IdentityResult idresultCreateUser = _userManager.CreateAsync(appUser, password).Result;

            if (!idresultCreateUser.Succeeded)
            {
                string msg = $"Failed to create user [{username}]";
                _logger.LogError(prefix + msg);
                throw new Exception(msg);
            }

            // User creation succeeded.

            // Add the roles

            if (!roles.Any())
            {
                _logger.LogDebug(prefix + $"Positive result; User [{username}] was created with no roles.");
                return;
            }

            string sRoles = string.Join(",", roles);
            IdentityResult idresultAddRoles = _userManager.AddToRolesAsync(appUser, roles).Result;

            if (!idresultAddRoles.Succeeded)
            {
                string msg = $"Failed to add roles [{sRoles}] for user [{username}]";
                _logger.LogError(prefix + msg);
                throw new Exception(msg);
            }

            _logger.LogDebug(prefix + $"Positive result; User [{username}] was created with roles [{sRoles}].");
        }

    }

    /*
    public class PrepareData
    {
        private readonly ILogger _logger;
        private readonly 

        private UserManager<ApplicationUser> _userManager;
        private RoleManager<ApplicationRole> _roleManager;

        private int _trigger = 0;





        public PrepareData(
            ILogger<PrepareData> logger,
            IConfigurationRoot config,
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            string prefix = "PrepareData" + Constants.FNSUFFIX + "[CTOR] ";

            _logger = logger;
            _config = config;
            _userManager = userManager;
            _roleManager = roleManager;

            _logger.LogDebug(prefix + "Entering");

            init();

            _logger.LogDebug(prefix + "Exiting");
        }


        private void init()
        {
            string prefix = nameof(init) + Constants.FNSUFFIX;

            createRoleIfNotExistent("ADMIN");
            createRoleIfNotExistent("USER");

            createUserIfNotExistent("Admin", "test123", new List<string> { "ADMIN", "USER" });
            createUserIfNotExistent("Alice", "test123", new List<string> { "USER" });
            createUserIfNotExistent("Bob", "test123", new List<string>());
            createUserIfNotExistent("Charlie", "test123", new List<string> { "ADMIN" });
        }


        private void createRoleIfNotExistent(string roleName)
        {
            string prefix = nameof(createRoleIfNotExistent) + Constants.FNSUFFIX;

            ApplicationRole appRoleExistent = _roleManager.FindByNameAsync(roleName).Result;

            if (appRoleExistent != null)
            {
                _logger.LogDebug(prefix + $"Positive result; Role [{roleName}] exists.  New role will not be created.");
                return;
            }

            // Role does not exist

            ApplicationRole appRole = new ApplicationRole
            {
                RoleName = roleName,
                RoleId = Guid.NewGuid().ToString(Constants.GUID_DB),
                ConcurrencyStamp = Guid.NewGuid().ToString(Constants.GUID_DB)
            };

            IdentityResult idresult = _roleManager.CreateAsync(appRole).Result;

            if (idresult.Succeeded)
            {
                _logger.LogDebug(prefix + $"Positive result; Role [{roleName}] did not exist, and was created.");
                return;
            }
            else
            {
                string msg = $"Failed to create role [{roleName}]";
                _logger.LogError(prefix + msg);
                throw new Exception(msg);
            }
        }

        private void createUserIfNotExistent(string username,string password, IEnumerable<string> roles)
        {
            string prefix = nameof(createUserIfNotExistent) + Constants.FNSUFFIX;

            ApplicationUser appUserExistent = _userManager.FindByNameAsync(username).Result;

            if (appUserExistent != null)
            {
                _logger.LogDebug(prefix + $"Positive result; User [{username}] exists.  New user will not be created.");
                return;
            }

            ApplicationUser appUser = new ApplicationUser
            {
                UserName = username,
                UserId = Guid.NewGuid().ToString(Constants.GUID_DB),
                Enabled = true,
                SecurityStamp = Guid.NewGuid().ToString(Constants.GUID_DB),
                ConcurrencyStamp = Guid.NewGuid().ToString(Constants.GUID_DB)
            };

            IdentityResult idresultCreateUser = _userManager.CreateAsync(appUser, password).Result;

            if (!idresultCreateUser.Succeeded)
            {
                string msg = $"Failed to create user [{username}]";
                _logger.LogError(prefix + msg);
                throw new Exception(msg);
            }

            // User creation succeeded.

            // Add the roles

            if (!roles.Any())
            {
                _logger.LogDebug(prefix + $"Positive result; User [{username}] was created with no roles.");
                return;
            }

            string sRoles = string.Join(",", roles);
            IdentityResult idresultAddRoles = _userManager.AddToRolesAsync(appUser, roles).Result;

            if (!idresultAddRoles.Succeeded)
            {
                string msg = $"Failed to add roles [{sRoles}] for user [{username}]";
                _logger.LogError(prefix + msg);
                throw new Exception(msg);
            }

            _logger.LogDebug(prefix + $"Positive result; User [{username}] was created with roles [{sRoles}].");
        }

        public int Trigger
        {
            get { return _trigger; }
            set { _trigger = value; }
        }
        
    }
    */
}
