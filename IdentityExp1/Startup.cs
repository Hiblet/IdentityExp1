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
        public IConfigurationRoot _configuration { get; }
        public ILogger _logger;


        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange:false)
                .AddEnvironmentVariables();
            _configuration = builder.Build();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            ///////////////////////////////////////////////////////////////////
            // Classes required for Identity 
            //

            // EXAMPLE
            /*
            var userStore = new ExampleUserStore();
            var roleStore = new ExampleRoleStore();
            var tokenStore = new ExampleTokenStore();
            services.AddSingleton<IUserStore<ExampleApplicationUser>>(userStore);
            services.AddSingleton<IUserPasswordStore<ExampleApplicationUser>>(userStore);
            services.AddSingleton<IUserEmailStore<ExampleApplicationUser>>(userStore);
            services.AddSingleton<IRoleStore<ExampleApplicationRole>>(roleStore);
            services.AddSingleton<ITokenStore<ApplicationJwtRefreshToken>>(tokenStore);
            services.AddSingleton<IUserClaimsPrincipalFactory<ExampleApplicationUser>, ExampleUserPrincipalFactory>();

            services.AddIdentity<ExampleApplicationUser, ExampleApplicationRole>(options =>
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
            */

            
            // ACTUAL
            //var userStore = new UserStore();                         
            services.AddSingleton<IUserStore<ApplicationUser>,UserStore>();
            services.AddSingleton<IUserPasswordStore<ApplicationUser>,UserStore>();
            services.AddSingleton<IUserEmailStore<ApplicationUser>,UserStore>();
            services.AddSingleton<ITokenStore<ApplicationJwtRefreshToken>,TokenStore>();
            services.AddSingleton<IRoleStore<ApplicationRole>, RoleStore>();
            services.AddSingleton<IUserClaimsPrincipalFactory<ApplicationUser>, UserPrincipalFactory>();

            services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                // Relaxed for testing...
                options.Password.RequiredLength = 6;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireDigit = false;
                options.Password.RequireNonAlphanumeric = false;
            });
            

            //
            ///////////////////////////////////////////////////////////////////



            ///////////////////////////////////////////////////////////////////
            // Configuration

            // Adds services required for using options.
            services.AddOptions();

            services.AddSingleton<IConfiguration>(_configuration); // Add the built config object to the Services container, making it injectable to a ctor.

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
            var jwtAppSettingOptions = _configuration.GetSection(nameof(JwtIssuerOptions));

            string secret = _configuration[Constants.SECRET_ENV_VAR] ?? "DEFAULT_SECRET_KEY"; // SECRET KEY MUST BE 16 CHARS OR MORE
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
            // Email Service
            //

            // Load the Options;
            // Requires:
            //  Nuget for MailKit.
            //  EmailOptions in appsettings.json .
            //  Password in Environment variables.

            services.Configure<EmailOptions>(_configuration.GetSection("EmailOptions"));
            services.Configure<EmailOptions>(options =>
                options.Password = _configuration.GetSection(EmailService.EMAIL_PASSWORD).Value);

            services.AddSingleton<EmailService>();

            //
            ///////////////////////////////////////////////////////////////////


            ///////////////////////////////////////////////////////////////////
            // HTTPS SSL
            // Dont forget to do Project.Properties.Debug EnableSSL

            services.Configure<MvcOptions>(options => { options.Filters.Add(new RequireHttpsAttribute()); });

            //
            ///////////////////////////////////////////////////////////////////



            ///////////////////////////////////////////////////////////////////
            // AspNetCoreRateLimit
            //

            services.AddMemoryCache();

            // Configure ip rate limiting middle-ware            
            services.Configure<IpRateLimitOptions>(_configuration.GetSection("IpRateLimiting"));
            services.Configure<IpRateLimitPolicies>(_configuration.GetSection("IpRateLimitPolicies"));
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

            ///////////////////////////////////////////////////////////////////
            // APP SPECIFIC

            var connectionStringsSection = _configuration.GetSection("ConnectionStrings");
            var connStrRaw = connectionStringsSection.GetSection("CustomIdentity").Value; // <- Value of conn string
            string connStrProcessed = connStrHelper(connStrRaw);

            services.Configure<CustomDynamicOptions>(_configuration); // Bind in my dynamic options structure to the config
            services.Configure<CustomDynamicOptions>(options => options.ConnStr = connStrProcessed); // Set the value to the created string, so it can be passed via injection.

            //
            ///////////////////////////////////////////////////////////////////


        }

        public void Configure(
            IApplicationBuilder app, 
            IHostingEnvironment env, 
            ILoggerFactory loggerFactory,
            EmailService emailService,
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            string prefix = nameof(Configure) + Constants.FNSUFFIX;

            loggerFactory.AddLog4Net(emailService);
            _logger = loggerFactory.CreateLogger<Startup>();

            ///////////////////////////////////////////////////////////////////
            // HTTPS SSL

            app.UseRewriter(new RewriteOptions().AddRedirectToHttps());

            //
            ///////////////////////////////////////////////////////////////////


            app.UseMiddleware<NZ01.LogRequestAndResponseMiddleware>(); 

            app.UseStatusCodePages();
            if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }

            app.UseStaticFiles(); 

            ///////////////////////////////////////////////////////////////////
            // HTTPS SSL (certification requirement)
            //
            // LetsEncrypt Acme Challenge:
            // Let's Encrypt will test whether or not you own a website by writing something to the 
            // site and expecting it to be available.  You have to create that directory and make that directory available.
            // Ref: https://www.softfluent.com/blog/dev/Using-Let-s-encrypt-with-ASP-NET-Core
            
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), @".well-known")),
                RequestPath = new PathString("/.well-known"),
                ServeUnknownFileTypes = true // serve extensionless file
            });
            
            //
            ///////////////////////////////////////////////////////////////////


            ///////////////////////////////////////////////////////////////////
            // JWT 

            // Authenticate before identity

            string secret = _configuration[Constants.SECRET_ENV_VAR] ?? "DEFAULT_SECRET_KEY"; // SECRET KEY MUST BE 16 CHARS OR MORE
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));

            var jwtAppSettingOptions = _configuration.GetSection(nameof(JwtIssuerOptions));

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

            //ExamplePrepareData.Init(userManager, roleManager);
            PrepareData.Init(userManager, roleManager,loggerFactory.CreateLogger<PrepareData>());

            _logger.LogWarning(prefix + $"Application Started [{env.EnvironmentName}]");
        }


        /// <summary>
        /// Function to take a connection string with a PasswordEnvVar placeholder,
        /// and create a genuine connection string, by substituting in the correct 
        /// password from an environment variable.
        /// </summary>
        /// <param name="connStrRaw"></param>
        /// <returns></returns>
        private string connStrHelper(string connStrRaw)
        {
            string targetKey = "PasswordEnvVar";
            string targetVal = "";
            string[] arrConnStrRaw = connStrRaw.Split(';');
            List<string> listConnStrRawClean = new List<string>();
            foreach (string kvp in arrConnStrRaw)
            {
                string[] arrKvp = kvp.Split('=');
                if (arrKvp.Count() == 2)
                {
                    if (arrKvp[0] == targetKey)
                    {
                        // If this is the PasswordEnvVar variable, 
                        // get the key, and do not add to clean list.
                        targetVal = arrKvp[1];
                    }
                    else
                    {
                        // Pass straight through to the clean list
                        listConnStrRawClean.Add(kvp);
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(targetVal))
                return connStrRaw;

            string password = _configuration.GetSection(targetVal).Value;

            if (string.IsNullOrWhiteSpace(password))
                return connStrRaw;

            listConnStrRawClean.Add("Password=" + password);
            return string.Join(";", listConnStrRawClean);
        }

    }
}
