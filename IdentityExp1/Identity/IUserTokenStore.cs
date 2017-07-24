using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using IdentityExp1.Models;
using System.Threading;

namespace IdentityExp1
{
    public interface IUserTokenStore<TUser, TToken> : IUserStore<TUser>, IDisposable 
        where TUser : class 
        where TToken : class
    {
        Task AddTokenAsync(TUser user, TToken tToken, CancellationToken cancellationToken);
        Task RemoveTokenAsync(string guid, CancellationToken cancellationToken);
        Task<TToken> GetTokenAsync(string guid, CancellationToken cancellationToken);
    }
}
