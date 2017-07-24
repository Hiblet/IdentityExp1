using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using System.Reflection; // PropertyInfo

namespace IdentityExp1.Controllers
{
    public class HomeController:Controller
    {
        private readonly NZ01.Options _options;
        private IConfiguration _config;

        public HomeController(
            IOptions<NZ01.Options> options,
            IConfiguration config)
        {
            _options = options.Value;
            _config = config;
        }

        [AllowAnonymous]
        public ViewResult Index()
        {
            Dictionary<string, object> testDic = new Dictionary<string, object>();
            testDic["Placeholder"] = "Placeholder";

            // Enumerate the Options
            foreach (PropertyInfo prop in typeof(NZ01.Options).GetProperties())
            {
                testDic[prop.Name] = prop.GetValue(_options).ToString();
            }

            // Enumerate the Config
            IEnumerable<KeyValuePair<string,string>> configEnum = _config.AsEnumerable();
            foreach (KeyValuePair<string, string> kvp in configEnum)
            {
                testDic[kvp.Key] = kvp.Value;
            }

            return View(testDic);
        }

        public ViewResult ActionA()
        {
            Dictionary<string, object> testDic = new Dictionary<string, object>();
            testDic["Action"] = "ActionA";
            testDic["Restriction"] = "Not Restricted";
            testDic["AllowAnonymous"] = "FALSE";
            testDic["Authorize"] = "FALSE";

            return View(nameof(Index), testDic);
        }

        [AllowAnonymous]
        public ViewResult ActionB()
        {
            Dictionary<string, object> testDic = new Dictionary<string, object>();
            testDic["Action"] = "ActionB";
            testDic["Restriction"] = "Not Restricted";
            testDic["AllowAnonymous"] = "TRUE";
            testDic["Authorize"] = "FALSE";

            return View(nameof(Index), testDic);
        }

        [Authorize] 
        // Authorize Attribute requires a ClaimsPrincipal with a ClaimsIdentity that has IsAuthenticated=true
        // Works as a filter.  Calcs current policy, builds a principal, checks for AllowAnonymous.
        // If not authenticated, returns challenge.
        public ViewResult ActionC()
        {
            Dictionary<string, object> testDic = new Dictionary<string, object>();
            testDic["Action"] = "ActionC";
            testDic["Restriction"] = "Not Restricted";
            testDic["AllowAnonymous"] = "FALSE";
            testDic["Authorize"] = "TRUE";

            return View(nameof(Index), testDic);
        }

    }
}
