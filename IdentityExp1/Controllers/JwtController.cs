using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

using NZ01;
using IdentityExp1.Models;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using IdentityExp1;
using System.Threading;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityExp1.Controllers
{
    [Route("api/[controller]/[action]")]    
    public class JwtController : Controller
    {
        private readonly JwtIssuerOptions _jwtOptions;
        private readonly ILogger _logger;
        private readonly JsonSerializerSettings _serializerSettings;
        private UserManager<ApplicationUser> _userManager;
        private ITokenStore<ApplicationJwtRefreshToken> _tokenStore;
        private readonly IConfiguration _configuration;

        // Keys for custom token values, to avoid magic strings
        public static readonly string GUIDKEY = "guid";
        public static readonly string NAMEKEY = "name";
        public static readonly string IPKEY = "ip";




        public JwtController(
            IOptions<JwtIssuerOptions> jwtOptions,
            UserManager<ApplicationUser> userManager,
            ITokenStore<ApplicationJwtRefreshToken> tokenStore,
            IConfiguration configuration,
            ILogger<JwtController> logger)
        {
            _jwtOptions = jwtOptions.Value;
            throwIfInvalidOptions(_jwtOptions);

            _logger = logger;

            _serializerSettings = new JsonSerializerSettings { Formatting = Formatting.Indented };
            _userManager = userManager;
            _tokenStore = tokenStore;
            _configuration = configuration;
        }



        /// <summary>
        /// Present valid username and password, and receive access and refresh token.
        /// </summary>
        /// <param name="creds">Object of type LoginCredentials; Simple wrapper for UserName and Password</param>
        /// <returns>
        /// On receipt of valid credentials, returns an access and refresh token.
        /// On receipt of invalid credentials, returns BadRequest.
        /// </returns>
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Issue(LoginCredentials creds)
        {
            string prefix = nameof(Issue) + Constants.FNSUFFIX;

            string sInvalid = "Invalid Credentials - ";

            if (!ModelState.IsValid) return BadRequest(sInvalid + "(A)");
            if (creds == null) return BadRequest(sInvalid + "(B)");
            if (string.IsNullOrWhiteSpace(creds.UserName)) return BadRequest(sInvalid + "(C)");
            if (string.IsNullOrWhiteSpace(creds.Password)) return BadRequest(sInvalid + "(D)");

            var identity = await getClaimsIdentity(creds); // creds=un+pw
            if (identity == null)
            {
                _logger.LogInformation(prefix + $"Invalid username ({creds.UserName}) or password ({creds.Password})");
                return BadRequest("Invalid credentials (E)");
            }

            string ip = AppUtility.GetRequestIP(HttpContext, true);

            return await issueTokens(identity, ip);
        }



        /// <summary>
        /// Receive a refresh token, and if valid, pull claims from database 
        /// and re-issue a new access and refresh token pair.
        /// </summary>
        /// <param name="sRefreshToken"></param>
        /// <returns>
        /// On receipt of a valid refresh token, new access and refresh tokens
        /// are attached as an array in the response body in Json format.
        /// On receipt of an invalid refresh token, BadRequest is returned.
        /// A proprietory code is added to the response body for forensics.
        /// </returns>
        /// <remarks>
        /// The refresh token sent back should be the string supplied in the
        /// second array element from the Issue action, without quotes.
        /// Example body: 
        ///  sRefreshToken=eyAahHen2djce...
        /// </remarks>
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Refresh(string sRefreshToken)
        {
            var prefix = "Refresh() - ";
            string msg = "";

            string sInvalid = "Invalid Refesh Token - ";

            if (!ModelState.IsValid)
                return BadRequest(sInvalid + "(A)");

            var handler = new JwtSecurityTokenHandler();

            string secret = _configuration[Constants.SECRET_ENV_VAR] ?? "DEFAULT_SECRET_KEY"; // SECRET KEY MUST BE 16 CHARS OR MORE
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _jwtOptions.Issuer,

                ValidateAudience = true,
                ValidAudience = _jwtOptions.Audience,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,

                RequireExpirationTime = true,
                ValidateLifetime = true,

                ClockSkew = TimeSpan.FromSeconds(_jwtOptions.RefreshClockSkew)
            };

            SecurityToken validatedToken = null;
            ClaimsPrincipal claimsPrincipal = null;
            try
            {
                claimsPrincipal = handler.ValidateToken(sRefreshToken, tokenValidationParameters, out validatedToken);
            }
            catch (Exception ex)
            {
                msg = $"Refresh Token failed JwtSecurityTokenHandler.ValidateToken(); Token:[{sRefreshToken}]; Ex:[{ex.Message}]; Base:[{ex.GetBaseException().Message}]";
                _logger.LogInformation(prefix + msg);
                return BadRequest(sInvalid + "(B)");
            }

            if (validatedToken == null)
                return BadRequest(sInvalid + "(C)");

            // OK, we have a valid refresh token.  Does it have the correct custom payload?
            var validatedJwtSecurityToken = validatedToken as JwtSecurityToken;
            if (validatedJwtSecurityToken == null)
                return BadRequest(sInvalid + "(D)");

            object objPayloadGuid = null;
            string sPayloadGuid = "";
            if (validatedJwtSecurityToken.Payload.TryGetValue(GUIDKEY, out objPayloadGuid))            
                sPayloadGuid = (objPayloadGuid == null) ? "" : (string)objPayloadGuid;

            if (string.IsNullOrWhiteSpace(sPayloadGuid))
                return BadRequest(sInvalid + "(E)");

            object objPayloadName = null;
            string sPayloadName = "";
            if (validatedJwtSecurityToken.Payload.TryGetValue(NAMEKEY, out objPayloadName))            
                sPayloadName = (objPayloadName == null) ? "" : (string)objPayloadName;

            if (string.IsNullOrWhiteSpace(sPayloadName))
                return BadRequest(sInvalid + "(F)");

            object objPayloadIP = null;
            string sPayloadIP = "";
            if (validatedJwtSecurityToken.Payload.TryGetValue(IPKEY, out objPayloadIP))
                sPayloadIP = (objPayloadIP == null) ? "" : (string)objPayloadIP;
            // IP address may be empty

            // Payload values are now known to not be null

            // Check against database.
            var appJwtRefreshToken = await _tokenStore.ExtractByGuidAsync(sPayloadGuid, new CancellationToken());

            if (!string.Equals(appJwtRefreshToken.Guid, sPayloadGuid, StringComparison.OrdinalIgnoreCase))
                return BadRequest(sInvalid + "(G)");

            if (!string.Equals(appJwtRefreshToken.Name, sPayloadName, StringComparison.OrdinalIgnoreCase))
                return BadRequest(sInvalid + "(H)");

            if (!string.Equals(appJwtRefreshToken.IP, sPayloadIP, StringComparison.OrdinalIgnoreCase))
                return BadRequest(sInvalid + "(I)");

            // Payload values match those in the database.

            // The token has an IP address in it;  The request has an IP address;  The database has the issued IP address;
            // If the incoming request's IP address differs from the recorded IP address, the user may have legitimately
            // switched IP addresses, or a legitimate refresh token may have been stolen by a bad actor and they may be
            // trying to get access tokens using a stolen token.  Force a re-authentication just in case.
            string ip = AppUtility.GetRequestIP(HttpContext, true);
            if (!string.Equals(ip, appJwtRefreshToken.IP))
                return BadRequest(sInvalid + "(I)");


            // If valid, re-pull the claims in case the roles have changed, 
            // or the user has been locked out for being evil, and re-issue.
            ApplicationUser user = _userManager.FindByNameAsync(sPayloadName).Result;
            if (user == null)
                return BadRequest($"User [{user.UserName}] not found");

            if (!user.Enabled)
                return BadRequest($"User [{user.UserName}] is not enabled");

            // We have an active user, who is not evil.
            // Re-pulling their claimsIdentity ensures that the new tokens issued have recent claims.

            ClaimsIdentity identity = getClaimsIdentityForAppUser(user).Result;
            return await issueTokens(identity,ip);
        }
        

        private async Task<IActionResult> issueTokens(ClaimsIdentity identity, string ip)
        {
            var prefix = "issueTokens() - ";

            _logger.LogInformation(prefix + $"Issuing new access and refresh tokens for username {identity.Name}");

            var jwtAccess = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: identity.Claims,
                notBefore: _jwtOptions.NotBefore,
                expires: _jwtOptions.AccessExpiration,
                signingCredentials: _jwtOptions.SigningCredentials);

            var jwtRefresh = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                //claims: identity.Claims,                
                //notBefore: _jwtOptions.NotBefore,
                expires: _jwtOptions.RefreshExpiration,
                signingCredentials: _jwtOptions.SigningCredentials);

            string refreshTokenGuid = Guid.NewGuid().ToString(); // Stamp in a custom payload
            string refreshTokenName = identity.Name;
            jwtRefresh.Payload[GUIDKEY] = refreshTokenGuid;
            jwtRefresh.Payload[NAMEKEY] = refreshTokenName;
            jwtRefresh.Payload[IPKEY] = ip;

            var handler = new JwtSecurityTokenHandler();
            var encodedJwtAccess = handler.WriteToken(jwtAccess);
            var encodedJwtRefresh = handler.WriteToken(jwtRefresh);

            // Build the object to return
            List<object> jwts = new List<object>();

            jwts.Add(new {
                access_token = encodedJwtAccess,
                expires_in = (int)_jwtOptions.AccessValidFor.TotalSeconds
            });

            jwts.Add(new {
                refresh_token = encodedJwtRefresh,
                expires_in = (int)_jwtOptions.RefreshValidFor.TotalSeconds
            });

            // Store refresh token in database
            await _tokenStore.CreateAsync(
                new ApplicationJwtRefreshToken { Guid = refreshTokenGuid, Name = refreshTokenName, IP = ip }, 
                new CancellationToken());

            // Serialize and return the response
            var json = JsonConvert.SerializeObject(jwts, _serializerSettings);
            return await Task.FromResult(new OkObjectResult(json));
        }

        /// <summary>
        /// Check options are valid
        /// </summary>
        /// <param name="options"></param>
        private static void throwIfInvalidOptions(JwtIssuerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.AccessValidFor <= TimeSpan.Zero) { throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.AccessValidFor)); }
            if (options.RefreshValidFor <= TimeSpan.Zero) { throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.RefreshValidFor)); }

            if (options.SigningCredentials == null) { throw new ArgumentNullException(nameof(JwtIssuerOptions.SigningCredentials)); }

            if (options.JtiGenerator == null) { throw new ArgumentNullException(nameof(JwtIssuerOptions.JtiGenerator)); }
        }

        /// <returns>Date converted to seconds since Unix epoch (Jan 1, 1970, midnight UTC).</returns>
        private static long toUnixEpochDate(DateTime date)
        {
            return (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
        }

        private Task<ClaimsIdentity> getClaimsIdentityForAppUser(ApplicationUser user)
        {
            var genericID = new GenericIdentity(user.UserName, "Token");
            var tokenID = _jwtOptions.JtiGenerator().Result;

            ICollection<Claim> claims = getRoleClaims(user);
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.UserName));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, tokenID));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, toUnixEpochDate(_jwtOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64));

            // Add any claims here that the consuming application may need when using an access token.
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));

            return Task.FromResult(new ClaimsIdentity(genericID, claims));
        }


        /// <summary>
        /// Check username and password, and if good, provide a Claims Identity
        /// </summary>
        /// <param name="creds">LoginCredentials; Simple type to contain UserName and Password</param>
        /// <returns></returns>
        private Task<ClaimsIdentity> getClaimsIdentity(LoginCredentials creds)
        {            
            if (string.IsNullOrWhiteSpace(creds.UserName)) return Task.FromResult<ClaimsIdentity>(null);
            if (string.IsNullOrWhiteSpace(creds.Password)) return Task.FromResult<ClaimsIdentity>(null);

            ApplicationUser user = _userManager.FindByNameAsync(creds.UserName).Result;
            if (user == null)
                return Task.FromResult<ClaimsIdentity>(null);

            bool isValid = _userManager.CheckPasswordAsync(user, creds.Password).Result;

            if (isValid)
                return getClaimsIdentityForAppUser(user);
            else
                return Task.FromResult<ClaimsIdentity>(null); // Credentials are invalid, or account doesn't exist
        }

        private ICollection<Claim> getRoleClaims(ApplicationUser user)
        {
            List<Claim> roleClaims = new List<Claim>();

            var roles = _userManager.GetRolesAsync(user).Result;

            foreach (string role in roles)            
                roleClaims.Add(new Claim(ClaimTypes.Role, role));
            
            return roleClaims;
        }

        /* Version for Memory Store example, where roles were stored as a string collection in the user.Roles property.
        /// <summary>
        /// Convert known roles to claims.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private static ICollection<Claim> getRoleClaims(ApplicationUser user)
        {
            List<Claim> roleClaims = new List<Claim>();

            foreach (string role in user.Roles)
                roleClaims.Add(new Claim(ClaimTypes.Role, role));

            return roleClaims;
        }
        */

        #region POLICY_TESTING

        /////////////////////////////////////////////////////////////////////// 
        //
        // ACTION TESTS
        //
        // ** Cut this region once satisfied with role based security testing **
        //
        // These actions have various access restrictions applied.
        // To test the restrictions, I first set the Access token to have a 
        // lifetime that will give me time to test all actions (10 mins)
        // and then set the refresh time greater than that.
        // Request an access token for Admin (via PostMan)...
        //  UserName=Admin&Password=test123
        //  HTTP:  POST http://localhost:61368/api/jwt/issue 
        //  HTTPS: POST http://localhost:44347/api/jwt/issue 
        // Try to access each action, by creating a GET request with header
        //  Authorize: Bearer <access_token>
        //  HTTP:  GET http://localhost:61368/api/jwt/testA
        //  HTTPS: GET http://localhost:44347/api/jwt/testA
        // Repeat for each action, and repeat whole process again for each user.
        // This should build a result grid as below...
        // 
        // No Authentication: Should only access TestA
        //  ------------------------------------------
        // | User               | Action   | Result   |
        //  ------------------------------------------
        // | Not Authenticated  | testA    | Y        |
        // |                    | testB    | N        |
        // |                    | testC    | N        |
        // |                    | testD    | N        |
        // |                    | testE    | N        |
        // |                    | testF    | N        |
        //  ------------------------------------------
        //
        // Admin: Should access all.  Total Domination.
        //  ------------------------------------------
        // | User               | Action   | Result   |
        //  ------------------------------------------
        // | Admin [User,Admin] | testA    | Y        |
        // |                    | testB    | Y        |
        // |                    | testC    | Y        |
        // |                    | testD    | Y        |
        // |                    | testE    | Y        |
        // |                    | testF    | Y        |
        //  ------------------------------------------
        //
        // Alice: Should be blocked on D and F
        //  ------------------------------------------
        // | User               | Action   | Result   |
        //  ------------------------------------------
        // | Alice [User]       | testA    | Y        |
        // |                    | testB    | Y        |
        // |                    | testC    | Y        |
        // |                    | testD    | N        |
        // |                    | testE    | Y        |
        // |                    | testF    | N        |
        //  ------------------------------------------
        //
        // Bob: Should be blocked on C, D, E and F.  Sorry Bob.
        //  ------------------------------------------
        // | User               | Action   | Result   |
        //  ------------------------------------------
        // | Bob []             | testA    | Y        |
        // |                    | testB    | Y        |
        // |                    | testC    | N        |
        // |                    | testD    | N        |
        // |                    | testE    | N        |
        // |                    | testF    | N        |
        //  ------------------------------------------
        //
        // Charlie: Should be blocked on C and F
        //  ------------------------------------------
        // | User               | Action   | Result   |
        //  ------------------------------------------
        // | Charlie [Admin]    | testA    | Y        |
        // |                    | testB    | Y        |
        // |                    | testC    | N        |
        // |                    | testD    | Y        |
        // |                    | testE    | Y        |
        // |                    | testF    | N        |
        //  ------------------------------------------

        [HttpGet]
        [AllowAnonymous] // Open to unauthenticated users
        public IActionResult TestA() { return Ok($"TestA Accessible to All; {DateTime.UtcNow}; " + diagnosticUserDetails()); }

        [HttpGet]
        //[AllowAnonymous] // Default lockdown, user must be authenticated
        public IActionResult TestB()
        { return Ok($"TestB Inaccessible to Unauthenticated Users; {DateTime.UtcNow}; " + diagnosticUserDetails()); }

        [HttpGet]
        [Authorize(Roles = "USER")] // Only authenticated users those with 'User' role
        public IActionResult TestC() { return Ok($"TestC should be accessible to authenticated Admin and Alice, but not authenticated Bob or Charlie; {DateTime.UtcNow}; " + diagnosticUserDetails()); }

        [HttpGet]
        [Authorize(Roles = "ADMIN")] // Only authenticated users those with 'Admin' role
        public IActionResult TestD() { return Ok($"TestD should be accessible to authenticated Admin or Charlie, but not authenticated Alice or Bob; {DateTime.UtcNow}; " + diagnosticUserDetails()); }

        [HttpGet]
        // Logical OR Policies
        [Authorize(Roles = "USER,ADMIN")] // Allow authenticated users those with 'Admin' OR 'User' role        
        public IActionResult TestE() { return Ok($"TestE should be accessible to authenticated Admin, Charlie or Alice, but not authenticated Bob; {DateTime.UtcNow}; " + diagnosticUserDetails()); }

        [HttpGet]
        // Logical AND Policies
        [Authorize(Roles = "USER")]
        [Authorize(Roles = "ADMIN")]
        public IActionResult TestF() { return Ok($"TestF should be accessible to authenticated Admin, but not authenticated Alice, Bob or Charlie; {DateTime.UtcNow}; " + diagnosticUserDetails()); }

        /*
        [HttpPost]
        [AllowAnonymous]
        public IActionResult TestPost(string sTest)
        {
            if (string.IsNullOrWhiteSpace(sTest))
                return BadRequest("String empty");
            else
                return Ok($"String was [{sTest}]");
        }
        */

        private string diagnosticUserDetails()
        {
            List<string> msgs = new List<string>();

            string username = HttpContext.User.Identity.Name ?? "";
            msgs.Add($"User:[{username}]");
            msgs.Add($"Authenticated:[{HttpContext.User.Identity.IsAuthenticated}]");
            msgs.Add($"AuthType:[{HttpContext.User.Identity.AuthenticationType}]");
            // Context should have a ClaimsPrincipal attached
            foreach (var claim in HttpContext.User.Claims)
            {
                msgs.Add($"ClaimType:[{claim.Type}], ClaimValue:[{claim.Value}], Issuer:[{claim.Issuer}]");
            }

            ApplicationUser user = _userManager.FindByNameAsync(username).Result;
            if (user == null)
                msgs.Add($"User [{username}] was not found in the database.");
            else
            {
                msgs.Add($"User [{username}] was found in the database.");
                bool isInRoleUser_UserManager = _userManager.IsInRoleAsync(user, "User").Result;
                bool isInRoleAdmin_UserManager = _userManager.IsInRoleAsync(user, "Admin").Result;
                msgs.Add($"IsInRole_UserManager(User):[{isInRoleUser_UserManager}]");
                msgs.Add($"IsInRole_UserManager(Admin):[{isInRoleAdmin_UserManager}]");

                bool isInRoleUser_ClaimsPrincipal = HttpContext.User.IsInRole("USER");
                bool isInRoleAdmin_ClaimsPrincipal = HttpContext.User.IsInRole("ADMIN");
                msgs.Add($"IsInRole_ClaimsPrincipal(User):[{isInRoleUser_ClaimsPrincipal}]");
                msgs.Add($"IsInRole_ClaimsPrincipal(Admin):[{isInRoleAdmin_ClaimsPrincipal}]");
            }

            return string.Join("<br />", msgs);
        }

        //
        ///////////////////////////////////////////////////////////////////////

        #endregion POLICY_TESTING

    }
}