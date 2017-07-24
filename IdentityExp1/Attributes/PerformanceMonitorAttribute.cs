using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.Diagnostics;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

namespace NZ01
{
    /// <summary>
    /// Apply to any action or controller that you want to profile the performance of.
    /// This is effectively redundant as the Microsoft.AspNetCore.Mvc.Internal.ControllerActionInvoker function logs the action time.
    /// DO NOT USE
    /// </summary>
    public class PerformanceMonitorAttribute : ActionFilterAttribute
    {
        public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var prefix = "OnActionExecutionAsync() - ";
            Stopwatch sw = Stopwatch.StartNew();
            await next();
            sw.Stop();
            //logger.LogDebug($"Processing time for Action [{context.ActionDescriptor.DisplayName}]: {sw.ElapsedMilliseconds} milliseconds");

            string msg = $"Processing time for Action [{context.ActionDescriptor.DisplayName}]: {sw.ElapsedMilliseconds} milliseconds";
            NZ01.Log4NetAsyncLog.Debug(prefix + msg);
        }

    }
}
