using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

using Microsoft.AspNetCore.Mvc;
using IdentityExp1;
using IdentityExp1.Controllers;
using IdentityExp1.Models;
using Moq;
using Microsoft.Extensions.Options;
using NZ01;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Security.Claims;

namespace IdentityExp1Test
{
    public class JwtControllerTest
    {
        [Fact]
        public void JwtController_Issue_HandlesBadInput()
        {
            ///////////////////////////////////////////////////////////////////
            // Arrange 
            //

            //   Options
            string secret = "A_KEY_MUST_BE_16_CHARS+";
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));
            SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            var jwtIssuerOptions = new JwtIssuerOptions
            {
                Issuer = "TokenIssuer",
                Audience = "TokenAudience",
                AccessValidFor = TimeSpan.FromSeconds(10),
                RefreshValidFor = TimeSpan.FromSeconds(100),
                AccessClockSkew = 0,
                RefreshClockSkew = 0,
                Subject = "Alice",
                SigningCredentials = signingCredentials
            };

            var mockOptions = new Mock<IOptions<JwtIssuerOptions>>();
            mockOptions.Setup(mo => mo.Value).Returns(jwtIssuerOptions);

            //   UserManager
            var fakeUserManager = new FakeUserManager();

            //   TokenStore
            var tokenStore = new ExampleTokenStore();

            //   Configuration
            var mockConfiguration = new Mock<IConfiguration>();
            mockConfiguration.SetupGet(m => m[Constants.SECRET_ENV_VAR]).Returns(secret);

            //   Logger
            var mockLogger = new Mock<ILogger<JwtController>>();

            JwtController controller = new JwtController(mockOptions.Object, fakeUserManager, tokenStore, mockConfiguration.Object, mockLogger.Object);

            // Credentials
            LoginCredentials creds = new LoginCredentials { UserName = "Alice", Password = "StupidPassword123" };
            LoginCredentials credsNoUsername = new LoginCredentials { Password = "StupidPassword123" };
            LoginCredentials credsNoPassword = new LoginCredentials { UserName = "Alice" };
            LoginCredentials credsEmpty = new LoginCredentials();

            // Act & Assert
            var actionResult = controller.Issue(null);
            Assert.Equal("Microsoft.AspNetCore.Mvc.BadRequestObjectResult", actionResult.Result.GetType().ToString());

            actionResult = controller.Issue(credsNoUsername);
            Assert.Equal("Microsoft.AspNetCore.Mvc.BadRequestObjectResult", actionResult.Result.GetType().ToString());

            actionResult = controller.Issue(credsNoPassword);
            Assert.Equal("Microsoft.AspNetCore.Mvc.BadRequestObjectResult", actionResult.Result.GetType().ToString());

            actionResult = controller.Issue(credsEmpty);
            Assert.Equal("Microsoft.AspNetCore.Mvc.BadRequestObjectResult", actionResult.Result.GetType().ToString());
        }


        [Fact]
        public void JwtController_Refresh_HandlesBadInput()
        {
            ///////////////////////////////////////////////////////////////////
            // Arrange 
            //

            //   Options
            string secret = "A_KEY_MUST_BE_16_CHARS+";
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));
            SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            var jwtIssuerOptions = new JwtIssuerOptions
            {
                Issuer = "TokenIssuer",
                Audience = "TokenAudience",
                AccessValidFor = TimeSpan.FromSeconds(10),
                RefreshValidFor = TimeSpan.FromSeconds(100),
                AccessClockSkew = 0,
                RefreshClockSkew = 0,
                Subject = "Alice",
                SigningCredentials = signingCredentials
            };

            var mockOptions = new Mock<IOptions<JwtIssuerOptions>>();
            mockOptions.Setup(mo => mo.Value).Returns(jwtIssuerOptions);

            //   UserManager
            var fakeUserManager = new FakeUserManager();

            //   TokenStore
            var tokenStore = new ExampleTokenStore();

            //   Configuration
            var mockConfiguration = new Mock<IConfiguration>();
            mockConfiguration.SetupGet(m => m[Constants.SECRET_ENV_VAR]).Returns(secret);

            //   Logger
            var mockLogger = new Mock<ILogger<JwtController>>();

            JwtController controller = new JwtController(mockOptions.Object, fakeUserManager, tokenStore, mockConfiguration.Object, mockLogger.Object);


            // Act & Assert          
            var actionResult = controller.Refresh(null);            
            Assert.Equal("Microsoft.AspNetCore.Mvc.BadRequestObjectResult", actionResult.Result.GetType().ToString());

            actionResult = controller.Refresh("TotalGarbage");
            Assert.Equal("Microsoft.AspNetCore.Mvc.BadRequestObjectResult", actionResult.Result.GetType().ToString());

            actionResult = controller.Refresh("");
            Assert.Equal("Microsoft.AspNetCore.Mvc.BadRequestObjectResult", actionResult.Result.GetType().ToString());
        }


        [Fact]
        public void JwtController_CanIssueTokens()
        {
            ///////////////////////////////////////////////////////////////////
            // Arrange 
            //

            //   Options
            string secret = "A_KEY_MUST_BE_16_CHARS+";
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));
            SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            var jwtIssuerOptions = new JwtIssuerOptions
            {
                Issuer = "TokenIssuer", Audience = "TokenAudience",
                AccessValidFor = TimeSpan.FromSeconds(10), RefreshValidFor = TimeSpan.FromSeconds(100),
                AccessClockSkew = 0, RefreshClockSkew = 0,
                Subject = "Alice", SigningCredentials = signingCredentials
            };

            var mockOptions = new Mock<IOptions<JwtIssuerOptions>>();
            mockOptions.Setup(mo => mo.Value).Returns(jwtIssuerOptions);

            //   UserManager
            var fakeUserManager = new FakeUserManager();

            //   TokenStore
            var tokenStore = new ExampleTokenStore();

            //   Configuration
            var mockConfiguration = new Mock<IConfiguration>();
            mockConfiguration.SetupGet(m => m[Constants.SECRET_ENV_VAR]).Returns(secret);

            //   Logger
            var mockLogger = new Mock<ILogger<JwtController>>();

            JwtController controller = new JwtController(mockOptions.Object, fakeUserManager, tokenStore, mockConfiguration.Object, mockLogger.Object);

            // Credentials
            LoginCredentials creds = new LoginCredentials { UserName = "Alice", Password = "StupidPassword123" };



            ///////////////////////////////////////////////////////////////////
            // Act
            //

            var result = controller.Issue(creds);


            ///////////////////////////////////////////////////////////////////
            // Assert
            //

            // Task should finish
            var resultStatus = result.Status;

            // Result should be 200 OK
            var actionResult = result.Result;

            checkActionResult(actionResult, jwtIssuerOptions, signingKey);
        }


        [Fact]
        public void JwtController_CanIssueAndRefreshTokens()
        {
            ///////////////////////////////////////////////////////////////////
            // Arrange 
            //

            //   Options
            string secret = "A_KEY_MUST_BE_16_CHARS+";
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));
            SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            var jwtIssuerOptions = new JwtIssuerOptions
            {
                Issuer = "TokenIssuer",
                Audience = "TokenAudience",
                AccessValidFor = TimeSpan.FromSeconds(10),
                RefreshValidFor = TimeSpan.FromSeconds(100),
                AccessClockSkew = 0,
                RefreshClockSkew = 0,
                Subject = "Alice",
                SigningCredentials = signingCredentials
            };

            var mockOptions = new Mock<IOptions<JwtIssuerOptions>>();
            mockOptions.Setup(mo => mo.Value).Returns(jwtIssuerOptions);

            //   UserManager
            var fakeUserManager = new FakeUserManager();

            //   TokenStore
            var tokenStore = new ExampleTokenStore();

            //   Configuration
            var mockConfiguration = new Mock<IConfiguration>();
            mockConfiguration.SetupGet(m => m[Constants.SECRET_ENV_VAR]).Returns(secret);

            //   Logger
            var mockLogger = new Mock<ILogger<JwtController>>();

            JwtController controller = new JwtController(mockOptions.Object, fakeUserManager, tokenStore, mockConfiguration.Object, mockLogger.Object);

            // Credentials
            LoginCredentials creds = new LoginCredentials { UserName = "Alice", Password = "StupidPassword123" };



            ///////////////////////////////////////////////////////////////////
            // Act
            //

            var issueResult = controller.Issue(creds);

            var typedActionIssueResult = issueResult.Result as Microsoft.AspNetCore.Mvc.OkObjectResult;

            Assert.NotNull(typedActionIssueResult);

            string issueBody = typedActionIssueResult.Value as string;

            Assert.NotNull(issueBody);

            dynamic objResponses = null;
            bool bDeserialized = true;
            try
            {
                objResponses = JsonConvert.DeserializeObject<List<dynamic>>(issueBody);
            }
            catch
            {
                bDeserialized = false;
            }

            Assert.True(bDeserialized);
            if (!bDeserialized)
                return;

            // objResponses should be a list of dynamic objects, the first of 
            // which should be an access token, the second of which should be
            // a refresh token
            var objResponse0 = objResponses[0]; // Access token wrapper
            var objResponse1 = objResponses[1]; // Refresh token wrapper

            string sRefreshToken = AppUtility.GetDynamicPropertyValueAsString(objResponse1, "refresh_token");

            // Call the Refresh endpoint with the token to see if a new pair of tokens are issued.

            var refreshResult = controller.Refresh(sRefreshToken);

            checkActionResult(refreshResult.Result, jwtIssuerOptions, signingKey);
        }

        // Assert that returned token pair is valid
        private void checkActionResult(IActionResult actionResult, JwtIssuerOptions jwtIssuerOptions, SymmetricSecurityKey signingKey)
        {
            var actionResultType = actionResult.GetType().ToString();
            Assert.Equal("Microsoft.AspNetCore.Mvc.OkObjectResult", actionResultType);

            // I should get back two tokens as json objects
            var typedActionResult = actionResult as Microsoft.AspNetCore.Mvc.OkObjectResult;
            Assert.NotNull(typedActionResult);
            if (typedActionResult == null)
                return;

            string body = typedActionResult.Value as string;
            Assert.NotNull(body);
            if (body == null)
                return;

            dynamic objResponses = null;
            bool bDeserialized = true;
            try
            {
                objResponses = JsonConvert.DeserializeObject<List<dynamic>>(body);
            }
            catch
            {
                bDeserialized = false;
            }

            Assert.True(bDeserialized);
            if (!bDeserialized)
                return;

            // objResponses should be a list of dynamic objects, the first of 
            // which should be an access token, the second of which should be
            // a refresh token
            int count = 0;
            foreach (var objResponse in objResponses)
                count++;

            Assert.Equal(2, count);
            if (count != 2) return;

            var objResponse0 = objResponses[0]; // Access token wrapper
            var objResponse1 = objResponses[1]; // Refresh token wrapper

            string sAccessToken = AppUtility.GetDynamicPropertyValueAsString(objResponse0, "access_token");
            string sRefreshToken = AppUtility.GetDynamicPropertyValueAsString(objResponse1, "refresh_token");
            Int64 iAccessExpiresIn = AppUtility.GetDynamicPropertyValueAsInt64(objResponse0, "expires_in", -1);
            Int64 iRefreshExpiresIn = AppUtility.GetDynamicPropertyValueAsInt64(objResponse1, "expires_in", -1);

            // Token strings should not be empty
            Assert.NotEqual(0, sAccessToken.Length);
            Assert.NotEqual(0, sRefreshToken.Length);

            // Expires values should not be null, Refresh value should always be greater than Access value
            Assert.True(iAccessExpiresIn > 0);
            Assert.True(iRefreshExpiresIn > 0);
            Assert.True(iRefreshExpiresIn > iAccessExpiresIn);

            // I should be able to decode those tokens, using the known secrets
            // and confirm that the details in the tokens are correct

            var handler = new JwtSecurityTokenHandler();

            var accessTokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtIssuerOptions.Issuer,
                ValidateAudience = true,
                ValidAudience = jwtIssuerOptions.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(jwtIssuerOptions.AccessClockSkew)
            };

            var refreshTokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtIssuerOptions.Issuer,
                ValidateAudience = true,
                ValidAudience = jwtIssuerOptions.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(jwtIssuerOptions.RefreshClockSkew)
            };

            SecurityToken validatedRefreshToken = null;
            var refreshClaimsPrincipal = handler.ValidateToken(sRefreshToken, refreshTokenValidationParameters, out validatedRefreshToken);
            Assert.NotNull(validatedRefreshToken);

            SecurityToken validatedAccessToken = null;
            var accessClaimsPrincipal = handler.ValidateToken(sAccessToken, accessTokenValidationParameters, out validatedAccessToken);
            Assert.NotNull(validatedAccessToken);

            // Cast to JwtSecurityToken
            var validatedRefreshJwtSecurityToken = validatedRefreshToken as JwtSecurityToken;
            Assert.NotNull(validatedRefreshJwtSecurityToken);

            var validatedAccessJwtSecurityToken = validatedAccessToken as JwtSecurityToken;
            Assert.NotNull(validatedAccessJwtSecurityToken);


            // AccessClaimsPrincipal should have 
            //  Identies collection count of 1
            //  Identity with Name property of Alice
            //  Identity property with some claims, including role of "User"

            int countIdentitiesA = 0;
            foreach (var possibleIdentityA in accessClaimsPrincipal.Identities)
                ++countIdentitiesA;
            Assert.Equal(1, countIdentitiesA);
            Assert.Equal("Alice", accessClaimsPrincipal.Identity.Name);

            int countClaimsA = 0;
            foreach (var possibleClaimA in accessClaimsPrincipal.Claims)
                ++countClaimsA;
            Assert.Equal(9, countClaimsA);

            Assert.True(accessClaimsPrincipal.HasClaim(ClaimTypes.Role, "User"));
            Assert.True(accessClaimsPrincipal.HasClaim(ClaimTypes.Name, "Alice"));


            // RefreshClaimsPrincipal should have Name, Guid and IP to validate against database.
            // Name and Guid may be strings, IP may be empty.

            int countIdentitiesR = 0;
            foreach (var possibleIdentityR in refreshClaimsPrincipal.Identities)
                ++countIdentitiesR;
            Assert.Equal(1, countIdentitiesR);

            int countClaimsR = 0;
            foreach (var possibleClaimR in refreshClaimsPrincipal.Claims)
                ++countClaimsR;
            Assert.Equal(6, countClaimsR);

            Assert.True(refreshClaimsPrincipal.HasClaim(c => c.Type == JwtController.GUIDKEY));
            Assert.True(refreshClaimsPrincipal.HasClaim(JwtController.NAMEKEY, "Alice"));
            Assert.True(refreshClaimsPrincipal.HasClaim(c => c.Type == JwtController.IPKEY));
        }

        [Fact]
        public void JwtController_RejectsStaleRefreshTokens()
        {
            ///////////////////////////////////////////////////////////////////
            // Arrange 
            //

            //   Options
            string secret = "A_KEY_MUST_BE_16_CHARS+";
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));
            SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            /////////////////////////
            int iAccessValidFor = 3; 
            int iRefreshValidFor = 6; // <- Short refresh time for testing
            /////////////////////////

            var jwtIssuerOptions = new JwtIssuerOptions
            {
                Issuer = "TokenIssuer",
                Audience = "TokenAudience",
                AccessValidFor = TimeSpan.FromSeconds(iAccessValidFor),
                RefreshValidFor = TimeSpan.FromSeconds(iRefreshValidFor),
                AccessClockSkew = 0,
                RefreshClockSkew = 0,
                Subject = "Alice",
                SigningCredentials = signingCredentials
            };

            var mockOptions = new Mock<IOptions<JwtIssuerOptions>>();
            mockOptions.Setup(mo => mo.Value).Returns(jwtIssuerOptions);

            //   UserManager
            var fakeUserManager = new FakeUserManager();

            //   TokenStore
            var tokenStore = new ExampleTokenStore();

            //   Configuration
            var mockConfiguration = new Mock<IConfiguration>();
            mockConfiguration.SetupGet(m => m[Constants.SECRET_ENV_VAR]).Returns(secret);

            //   Logger
            var mockLogger = new Mock<ILogger<JwtController>>();

            JwtController controller = new JwtController(mockOptions.Object, fakeUserManager, tokenStore, mockConfiguration.Object, mockLogger.Object);

            // Credentials
            LoginCredentials creds = new LoginCredentials { UserName = "Alice", Password = "StupidPassword123" };



            ///////////////////////////////////////////////////////////////////
            // Act
            //

            var issueResult = controller.Issue(creds);

            var typedActionIssueResult = issueResult.Result as Microsoft.AspNetCore.Mvc.OkObjectResult;

            Assert.NotNull(typedActionIssueResult);

            string issueBody = typedActionIssueResult.Value as string;

            Assert.NotNull(issueBody);

            dynamic objResponses = null;
            bool bDeserialized = true;
            try
            {
                objResponses = JsonConvert.DeserializeObject<List<dynamic>>(issueBody);
            }
            catch
            {
                bDeserialized = false;
            }

            Assert.True(bDeserialized);
            if (!bDeserialized)
                return;

            // objResponses should be a list of dynamic objects, the first of 
            // which should be an access token, the second of which should be
            // a refresh token
            var objResponse0 = objResponses[0]; // Access token wrapper
            var objResponse1 = objResponses[1]; // Refresh token wrapper

            string sRefreshToken = AppUtility.GetDynamicPropertyValueAsString(objResponse1, "refresh_token");

            // ALLOW TIME TO ELAPSE SO THAT THE REFRESH TOKEN IS STALE
            System.Threading.Thread.Sleep(1000 * (iRefreshValidFor + 1)); // Sleep for at least the timeout time of the refresh token, plus 1 second

            // Call the Refresh endpoint with the token to see if a new pair of tokens are issued.
            var refreshResult = controller.Refresh(sRefreshToken);

            ///////////////////////////////////////////////////////////////////
            // Assert
            //

            var actionResult = refreshResult.Result;            

            Assert.Equal("Microsoft.AspNetCore.Mvc.BadRequestObjectResult", actionResult.GetType().ToString());
        }

        [Fact]
        public void JwtController_RefreshTokenClockSkewWorks()
        {
            ///////////////////////////////////////////////////////////////////
            // Arrange 
            //

            //   Options
            string secret = "A_KEY_MUST_BE_16_CHARS+";
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret.PadRight(16)));
            SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            /////////////////////////
            int iAccessValidFor = 3;
            int iRefreshValidFor = 6; // <- Short refresh time for testing
            UInt32 iRefreshClockSkew = 5; 
            /////////////////////////

            var jwtIssuerOptions = new JwtIssuerOptions
            {
                Issuer = "TokenIssuer",
                Audience = "TokenAudience",
                AccessValidFor = TimeSpan.FromSeconds(iAccessValidFor),
                RefreshValidFor = TimeSpan.FromSeconds(iRefreshValidFor),
                AccessClockSkew = 0,
                RefreshClockSkew = iRefreshClockSkew,
                Subject = "Alice",
                SigningCredentials = signingCredentials
            };

            var mockOptions = new Mock<IOptions<JwtIssuerOptions>>();
            mockOptions.Setup(mo => mo.Value).Returns(jwtIssuerOptions);

            //   UserManager
            var fakeUserManager = new FakeUserManager();

            //   TokenStore
            var tokenStore = new ExampleTokenStore();

            //   Configuration
            var mockConfiguration = new Mock<IConfiguration>();
            mockConfiguration.SetupGet(m => m[Constants.SECRET_ENV_VAR]).Returns(secret);

            //   Logger
            var mockLogger = new Mock<ILogger<JwtController>>();

            JwtController controller = new JwtController(mockOptions.Object, fakeUserManager, tokenStore, mockConfiguration.Object, mockLogger.Object);

            // Credentials
            LoginCredentials creds = new LoginCredentials { UserName = "Alice", Password = "StupidPassword123" };



            ///////////////////////////////////////////////////////////////////
            // Act
            //

            var issueResult = controller.Issue(creds);

            var typedActionIssueResult = issueResult.Result as Microsoft.AspNetCore.Mvc.OkObjectResult;

            Assert.NotNull(typedActionIssueResult);

            string issueBody = typedActionIssueResult.Value as string;

            Assert.NotNull(issueBody);

            dynamic objResponses = null;
            bool bDeserialized = true;
            try
            {
                objResponses = JsonConvert.DeserializeObject<List<dynamic>>(issueBody);
            }
            catch
            {
                bDeserialized = false;
            }

            Assert.True(bDeserialized);
            if (!bDeserialized)
                return;

            // objResponses should be a list of dynamic objects, the first of 
            // which should be an access token, the second of which should be
            // a refresh token
            var objResponse0 = objResponses[0]; // Access token wrapper
            var objResponse1 = objResponses[1]; // Refresh token wrapper

            string sRefreshToken = AppUtility.GetDynamicPropertyValueAsString(objResponse1, "refresh_token");

            // ALLOW TIME TO ELAPSE SO THAT THE REFRESH TOKEN IS STALE IF
            // ZERO CLOCK SKEW, BUT JUST ABOUT ACCEPTABLE IF CLOCK SKEW IS WORKING
            System.Threading.Thread.Sleep(1000 * (iRefreshValidFor + (int)iRefreshClockSkew - 2)); // Sleep for at least the timeout time of the refresh token, plus 1 second

            // Call the Refresh endpoint with the token to see if a new pair of tokens are issued.
            var refreshResult = controller.Refresh(sRefreshToken);

            ///////////////////////////////////////////////////////////////////
            // Assert
            //

            var actionResult = refreshResult.Result;

            Assert.Equal("Microsoft.AspNetCore.Mvc.OkObjectResult", actionResult.GetType().ToString());
        }



    }
}
