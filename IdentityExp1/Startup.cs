using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc;
using IdentityExp1.Models;
using Microsoft.Extensions.Configuration;
using NZ01;
using Microsoft.IdentityModel.Tokens; // SymmetricSecurityKey
using System.Text;
using System.Security.Claims;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.Extensions.FileProviders;
using System.IO;

namespace IdentityExp1
{
    public class Startup
    {
        public IConfigurationRoot Configuration { get; }

        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange:false)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            ///////////////////////////////////////////////////////////////////
            // Classes required for Identity
            //

            var userStore = new ExampleUserStore();
            var roleStore = new ExampleRoleStore();
            var tokenStore = new ExampleTokenStore();
            services.AddSingleton<IUserStore<ApplicationUser>>(userStore);
            services.AddSingleton<IUserPasswordStore<ApplicationUser>>(userStore);
            services.AddSingleton<IUserEmailStore<ApplicationUser>>(userStore);
            services.AddSingleton<IRoleStore<ApplicationRole>>(roleStore);
            services.AddSingleton<ITokenStore<ApplicationJwtRefreshToken>>(tokenStore);
            services.AddSingleton<IUserClaimsPrincipalFactory<ApplicationUser>, ExampleUserPrincipalFactory>();

            services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                // Relaxed for testing...
                options.Password.RequiredLength = 6;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireDigit = false;
                options.Password.RequireNonAlphanumeric = false;
            });
            //.AddDefaultTokenProviders();

            // AddDefaultTokenProviders: Used to add providers for opaque account operation tokens.
            // Try removing.

            //
            ///////////////////////////////////////////////////////////////////



            ///////////////////////////////////////////////////////////////////
            // Configuration

            // Adds services required for using options.
            services.AddOptions();

            // Register the IConfiguration instance which MyOptions binds against.
            services.Configure<NZ01.Options>(Configuration); // Class NZ01.Options holds system-wide variables

            // Override loaded options if you wish with delegates
            services.Configure<NZ01.Options>(myOptions => { myOptions.Option1 = "This data held in Startup.cs"; });

            services.AddSingleton<IConfiguration>(Configuration); // Add the built config object to the Services container, making it injectable to a ctor.

            //
            ///////////////////////////////////////////////////////////////////

            ///////////////////////////////////////////////////////////////////
            // IIS

            // We are using JWTs, so the app.UseJwtBearerAuthentication setting 
            // should dictate how authentication is done.
            services.Configure<IISOptions>(options => {
                options.AutomaticAuthentication = false;
                options.ForwardClientCertificate = false;
                options.ForwardWindowsAuthentication = false;
            });

            //
            ///////////////////////////////////////////////////////////////////

            ///////////////////////////////////////////////////////////////////
            // JWT

            // Get options from app settings
            var jwtAppSettingOptions = Configuration.GetSection(nameof(JwtIssuerOptions));

            string secret = Configuration[Constants.SECRET_ENV_VAR] ?? "DEFAULT_SECRET_KEY"; // SECRET KEY MUST BE 16 CHARS OR MORE
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));

            // Configure JwtIssuerOptions
            var accessValidFor = jwtAppSettingOptions[nameof(JwtIssuerOptions.AccessValidFor)] ?? "";
            int iAccessValidFor = 0;

            var refreshValidFor = jwtAppSettingOptions[nameof(JwtIssuerOptions.RefreshValidFor)] ?? "";
            int iRefreshValidFor = 0;

            var accessClockSkew = jwtAppSettingOptions[nameof(JwtIssuerOptions.AccessClockSkew)] ?? "";
            UInt32 iAccessClockSkew = 0;

            var refreshClockSkew = jwtAppSettingOptions[nameof(JwtIssuerOptions.RefreshClockSkew)] ?? "";
            UInt32 iRefreshClockSkew = 0;

            services.Configure<JwtIssuerOptions>(options =>
            {
                options.Issuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
                options.Audience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)];
                options.SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

                if (Int32.TryParse(accessValidFor, out iAccessValidFor)) options.AccessValidFor = TimeSpan.FromSeconds(iAccessValidFor);
                if (Int32.TryParse(refreshValidFor, out iRefreshValidFor)) options.RefreshValidFor = TimeSpan.FromSeconds(iRefreshValidFor);

                if (UInt32.TryParse(accessClockSkew, out iAccessClockSkew)) options.AccessClockSkew = iAccessClockSkew;
                if (UInt32.TryParse(refreshClockSkew, out iRefreshClockSkew)) options.AccessClockSkew = iRefreshClockSkew;
            });

            //
            ///////////////////////////////////////////////////////////////////

            // Make authentication compulsory across the board (i.e. shut
            // down EVERYTHING unless explicitly opened up).
            
            // A - No block
            //services.AddMvc(); 

            // B - Block: All actions require authentication unless marked with [AllowAnonymous] attribute
            services.AddMvc(config =>
            {
                var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
                config.Filters.Add(new AuthorizeFilter(policy));
            });

            // Use policy auth. (example)
            //services.AddAuthorization(options =>
            //{
            //    options.AddPolicy(
            //        "DisneyUser",
            //        policy => policy.RequireClaim("DisneyCharacter", "IAmMickey"));
            //});



            ///////////////////////////////////////////////////////////////////
            // HTTPS SLL

            services.Configure<MvcOptions>(options => { options.Filters.Add(new RequireHttpsAttribute()); });

            //
            ///////////////////////////////////////////////////////////////////



            ///////////////////////////////////////////////////////////////////
            // AspNetCoreRateLimit
            //

            services.AddMemoryCache();

            // Configure ip rate limiting middle-ware            
            services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimiting"));
            services.Configure<IpRateLimitPolicies>(Configuration.GetSection("IpRateLimitPolicies"));
            services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
            
            // Configure client rate limiting middleware
            /*
            services.Configure<ClientRateLimitOptions>(Configuration.GetSection("ClientRateLimiting"));
            services.Configure<ClientRateLimitPolicies>(Configuration.GetSection("ClientRateLimitPolicies"));
            services.AddSingleton<IClientPolicyStore, MemoryCacheClientPolicyStore>();
            */

            // Both IP and/or Client Rate Limit middleware need a RateLimitCounterStore
            services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();

            //
            ///////////////////////////////////////////////////////////////////

        }

        public void Configure(
            IApplicationBuilder app, 
            IHostingEnvironment env, 
            ILoggerFactory loggerFactory, 
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            var prefix = "Configure() - ";

            loggerFactory.AddLog4Net();

            ///////////////////////////////////////////////////////////////////
            // HTTPS SSL

            app.UseRewriter(new RewriteOptions().AddRedirectToHttps());

            //
            ///////////////////////////////////////////////////////////////////


            app.UseMiddleware<NZ01.LogRequestAndResponseMiddleware>(); 

            app.UseStatusCodePages();
            if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }

            //app.UseStaticFiles(); // Should be removed, as element below makes this redundant?

            // HTTPS SSL (certification requirement)
            // LetsEncrypt Acme Challenge:
            // Let's Encrypt will test whether or not you own a website by writing something to the 
            // site and expecting it to be available.  You have to make that directory available.
            // Ref: https://www.softfluent.com/blog/dev/Using-Let-s-encrypt-with-ASP-NET-Core
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), @".well-known")),
                RequestPath = new PathString("/.well-known"),
                ServeUnknownFileTypes = true // serve extensionless file
            });


            ///////////////////////////////////////////////////////////////////
            // JWT 

            // Authenticate before identity

            string secret = Configuration[Constants.SECRET_ENV_VAR] ?? "DEFAULT_SECRET_KEY"; // SECRET KEY MUST BE 16 CHARS OR MORE
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));

            var jwtAppSettingOptions = Configuration.GetSection(nameof(JwtIssuerOptions));

            var accessClockSkew = jwtAppSettingOptions[nameof(JwtIssuerOptions.AccessClockSkew)] ?? "";
            UInt32 iAccessClockSkew = 0;
            UInt32.TryParse(accessClockSkew, out iAccessClockSkew);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)],

                ValidateAudience = true,
                ValidAudience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)],

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,

                RequireExpirationTime = true,
                ValidateLifetime = true,

                ClockSkew = TimeSpan.FromSeconds(iAccessClockSkew)
            };

            
            app.UseJwtBearerAuthentication(new JwtBearerOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,                
                TokenValidationParameters = tokenValidationParameters
            });
            

            //
            ///////////////////////////////////////////////////////////////////

            app.UseIdentity();

            ///////////////////////////////////////////////////////////////////
            // AspNetCoreRateLimit;
            // Note: Check ConfigureServices() has required objects inst'd.

            //app.UseClientRateLimiting();
            app.UseIpRateLimiting();

            ///////////////////////////////////////////////////////////////////

            app.UseMvcWithDefaultRoute();




            ///////////////////////////////////////////////////////////////////
            // TEST DATA            
            // As this is a memory based Identity implementation, we have to
            // seed the "database" with users and roles for testing.
            

            // Populate Roles
            var role = new ApplicationRole { RoleName = "Admin", RoleId = "Admin" };
            IdentityResult roleResult = roleManager.CreateAsync(role).Result;
            if (!roleResult.Succeeded) throw new Exception("Failed to create role Admin");

            role = new ApplicationRole { RoleName = "User", RoleId = "User" };
            roleResult = roleManager.CreateAsync(role).Result;
            if (!roleResult.Succeeded) throw new Exception("Failed to create role User");


            // Populate Users
            var userAdmin = new ApplicationUser { UserName = "Admin", Email="admin@example.com" };
            if (!userManager.CreateAsync(userAdmin, "test123").Result.Succeeded)
                throw new Exception("Failed to create user Admin");

            var userAlice = new ApplicationUser { UserName = "Alice", Email = "alice@example.com" };
            if (!userManager.CreateAsync(userAlice, "test123").Result.Succeeded)
                throw new Exception("Failed to create user Alice");

            var userBob = new ApplicationUser { UserName = "Bob", Email = "bob@example.com" };
            if (!userManager.CreateAsync(userBob, "test123").Result.Succeeded)
                throw new Exception("Failed to create user Bob");

            var userCharlie = new ApplicationUser { UserName = "Charlie", Email = "charlie@example.com" };
            if (!userManager.CreateAsync(userCharlie, "test123").Result.Succeeded)
                throw new Exception("Failed to create user Charlie");



            // Apply Roles 

            // Admin user is in [User,Admin] roles
            if (!userManager.AddToRoleAsync(userAdmin, "User").Result.Succeeded)
                throw new Exception("Failed to set role");

            if (!userManager.AddToRoleAsync(userAdmin, "Admin").Result.Succeeded)
                throw new Exception("Failed to set role");


            // Alice user is in [User] role
            if (!userManager.AddToRoleAsync(userAlice, "User").Result.Succeeded)
                throw new Exception("Failed to set role");


            // Bob is not in any role (sadface).

            // Charlie is purely an [Admin]
            if (!userManager.AddToRoleAsync(userCharlie, "Admin").Result.Succeeded)
                throw new Exception("Failed to set role");

            //
            ///////////////////////////////////////////////////////////////////

            var logger = loggerFactory.CreateLogger<Startup>();
            logger.LogInformation(prefix + $"Startup completed for environment [{env.EnvironmentName}]");
        }


    }
}
