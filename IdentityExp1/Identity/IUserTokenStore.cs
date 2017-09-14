using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using IdentityExp1.Models;
using System.Threading;

namespace NZ01
{
    public interface IUserTokenStore<TToken> 
        where TToken : class
    {
        Task InsertTokenAsync(TToken tToken, CancellationToken cancellationToken);
        Task<TToken> ExtractTokenAsync(string guid, CancellationToken cancellationToken);
    }

    /*
    public interface IUserTokenStore<TUser, TToken> : IUserStore<TUser>, IDisposable 
        where TUser : class 
        where TToken : class
    {
        Task AddTokenAsync(TUser user, TToken tToken, CancellationToken cancellationToken);
        Task RemoveTokenAsync(string guid, CancellationToken cancellationToken);
        Task<TToken> GetTokenAsync(string guid, CancellationToken cancellationToken);
    }
    */
}
