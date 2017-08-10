using System;
using System.Collections.Generic;
using System.Text;

namespace NZ01
{
    public class EmailOptions
    {
        public string To { get; set; }
        public string From { get; set; }
        public string Host { get; set; }
        public bool EnableSsl { get; set; } = false;
        public int Port { get; set; } = 0;
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
