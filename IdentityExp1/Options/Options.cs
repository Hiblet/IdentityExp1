using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace NZ01
{
    public class Options 
    {
        // Ref: https://docs.microsoft.com/en-us/aspnet/core/fundamentals/configuration
        //
        // Add fields/properties here that can override settings in appsettings.json
        // The Startup will overlay these settings on to variables set in the config file.
        // In a client class that wishes to access the config, plus the options, 
        // inject "IOptions<NZ01.Options> optionsAccessor" as a constructor argument, 
        // that is saved as a class field, and then the client class can access
        // optionsAccessor.Option1 as a value.
        // TESTS: 
        //  Is this Option class a static instance? 
        //  Does a change in one class replicate to another?
        //  Are there thread concerns? 
        //  My suspicion is that you get a copy of the data, so changes to not replicate.
        
        public string Option1 { get; set; } = "This data is held in NZ01.Options";

        public Options() { }
    }
}
