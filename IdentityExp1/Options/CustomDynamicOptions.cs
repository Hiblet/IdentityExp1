using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NZ01
{
    /// <summary>
    /// Dynamic options are not stored in config files, they are built at runtime from other options or data.
    /// </summary>
    public class CustomDynamicOptions
    {
        public string ConnStr { get; set; } = "NOT_YET_BUILT";
    }
}
