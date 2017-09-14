using System;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.AspNetCore.Identity;

namespace NZ01
{
    public interface ITokenStore<TToken> : IDisposable where TToken : class
    {
        Task<IdentityResult> CreateAsync(TToken tToken, CancellationToken cancellationToken);
        Task<IdentityResult> DeleteAsync(string guid, CancellationToken cancellationToken);

        Task<TToken> FindByGuidAsync(string guid, CancellationToken cancellationToken); // Find and leave
        Task<TToken> ExtractByGuidAsync(string guid, CancellationToken cancellationToken); // Find and remove
    }
}
