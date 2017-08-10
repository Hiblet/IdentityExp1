using System;
using System.Collections.Generic;
using System.Text;

using Newtonsoft.Json;

namespace NZ01
{
    public class EmailContext
    {
        public string To { get; set; }
        public string From { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }

        public List<string> Errors { get; } = new List<string>();

        public bool IsCompleted { get; set; }
    }
}
