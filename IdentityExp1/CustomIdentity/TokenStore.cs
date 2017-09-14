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
    public class TokenStore : ITokenStore<ApplicationJwtRefreshToken>
    {
        public readonly ILogger _logger;
        public readonly string _connStr;
        public readonly CustomDynamicOptions _options;



        public TokenStore(ILogger<RoleStore> logger, IOptions<CustomDynamicOptions> optionsContainer)
        {
            _logger = logger;
            _options = optionsContainer.Value;
            _connStr = _options.ConnStr;
        }

        public Task<IdentityResult> CreateAsync(ApplicationJwtRefreshToken token, CancellationToken cancellationToken)
        {
            try
            {
                using (var tokensDAL = new AspNetTokensDAL(_connStr))
                {
                    tokensDAL.Insert(token);
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


        public Task<IdentityResult> DeleteAsync(string guid, CancellationToken cancellationToken)
        {
            try
            {
                using (var tokensDAL = new AspNetTokensDAL(_connStr))
                {
                    tokensDAL.Delete(guid);
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


        public Task<ApplicationJwtRefreshToken> FindByGuidAsync(string guid, CancellationToken cancellationToken)
        {
            string prefix = nameof(FindByGuidAsync) + Constants.FNSUFFIX;

            ApplicationJwtRefreshToken token = null;
            try
            {
                using (var tokensDAL = new AspNetTokensDAL(_connStr))
                {
                    token = tokensDAL.SelectByGuid(guid);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
            }

            return Task.FromResult(token);
        }

        public Task<ApplicationJwtRefreshToken> ExtractByGuidAsync(string guid, CancellationToken cancellationToken)
        {
            string prefix = nameof(ExtractByGuidAsync) + Constants.FNSUFFIX;

            ApplicationJwtRefreshToken token = null;
            try
            {
                using (var tokensDAL = new AspNetTokensDAL(_connStr))
                {
                    token = tokensDAL.SelectByGuid(guid);
                    if (token != null)
                    {
                        tokensDAL.Delete(guid);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(prefix + $"Exception:[{ex.ToString()}]");
            }

            return Task.FromResult(token);
        }

        public void Dispose() { }

    }
}
