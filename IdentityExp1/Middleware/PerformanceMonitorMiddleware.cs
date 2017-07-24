using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using System.Diagnostics;

namespace NZ01
{
    /// <summary>
    /// Middleware to log execution times.  PerformanceMonitorAttribute may be preferrable.
    /// This is effectively redundant, as the Microsoft.AspNetCore.Mvc.Internal.ControllerActionInvoker function logs this info
    /// DO NOT USE
    /// </summary>
    public class PerformanceMonitorMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<PerformanceMonitorMiddleware> _logger;

        public PerformanceMonitorMiddleware(RequestDelegate next, ILogger<PerformanceMonitorMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            Stopwatch sw = Stopwatch.StartNew();
            await _next(context);
            sw.Stop();
            // Might be nice to get the action from the route data here and log that, but how?
            // Single step at THIS POINT and examing the context to try to find the action method name.
            _logger.LogDebug($"Processing time: {sw.ElapsedMilliseconds} milliseconds");
        }

    }
}
