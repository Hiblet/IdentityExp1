using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.AspNetCore.Identity;
using IdentityExp1.Models;


namespace IdentityExp1
{
    public class ExampleTokenStore : ITokenStore<ApplicationJwtRefreshToken>
    {
        private Dictionary<string, Tuple<string,string>> _tokens; // Guid to Name/IP tuple pair

        public ExampleTokenStore()
        {
            _tokens = new Dictionary<string, Tuple<string,string>>();
        }

        public Task<IdentityResult> CreateAsync(ApplicationJwtRefreshToken token, CancellationToken ctoken)
        {
            var tuple = new Tuple<string, string>(token.Name, token.IP);
            _tokens[token.Guid] = tuple;

            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> DeleteAsync(string guid, CancellationToken ctoken)
        {
            _tokens.Remove(guid);

            return Task.FromResult(IdentityResult.Success);
        }


        public Task<ApplicationJwtRefreshToken> FindByGuidAsync(string guid, CancellationToken ctoken)
        {
            return findOrExtractByGuidAsync(guid, false, ctoken);
        }

        public Task<ApplicationJwtRefreshToken> ExtractByGuidAsync(string guid, CancellationToken ctoken)
        {
            return findOrExtractByGuidAsync(guid, true, ctoken);
        }

        private Task<ApplicationJwtRefreshToken> findOrExtractByGuidAsync(string guid, bool extract, CancellationToken ctoken)
        {
            //string name = "";
            Tuple<string, string> tuple = new Tuple<string, string>("","");

            if (_tokens.TryGetValue(guid, out tuple))
            {
                if (extract)
                    _tokens.Remove(guid);

                return Task.FromResult(new ApplicationJwtRefreshToken { Guid = guid, Name = tuple.Item1, IP = tuple.Item2 });
            }

            // Fail, return empty token
            return Task.FromResult(new ApplicationJwtRefreshToken());
        }

        public void Dispose() { }
    }
}
