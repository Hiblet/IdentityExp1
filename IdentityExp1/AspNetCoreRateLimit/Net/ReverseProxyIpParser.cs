﻿using System;
using System.Linq;
using System.Net;
using Microsoft.AspNetCore.Http;

namespace AspNetCoreRateLimit
{
    public class ReverseProxyIpParser : RemoteIpParser
    {
        private readonly string _realIpHeader;

        public ReverseProxyIpParser(string realIpHeader)
        {
            _realIpHeader = realIpHeader;
        }

        public override IPAddress GetClientIp(HttpContext context)
        {
            if (context.Request.Headers.Keys.Contains(_realIpHeader, StringComparer.CurrentCultureIgnoreCase))
            {
                return ParseIp(context.Request.Headers[_realIpHeader].Last());
            }

            return base.GetClientIp(context);
        }
    }
}
