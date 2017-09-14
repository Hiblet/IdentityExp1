using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace NZ01
{

    /*
    public interface IConnStrBuilder
    {
        string GetConnectionString();
    }

    /// <summary>
    /// Class to substitute environment variable password into connection string
    /// </summary>
    public class ConnStrBuilder : IConnStrBuilder
    {
        private readonly IConfigurationRoot _config;
        private readonly string _connStr = "FAILED";
        private readonly ILogger _logger;

        private int _nonce = 0;

        public ConnStrBuilder(IConfigurationRoot config, ILogger<ConnStrBuilder> logger)
        {
            _config = config;
            _logger = logger;
        }

        public string GetConnectionString()
        {
            if (_nonce == 0)
            {
                setConnectionString("CustomIdentity", _config);
                _nonce = 1;
            }

            return _connStr;
        }

        /// <summary>
        /// Take a connection string, find the key for the environment variable, add the password stored in the environment variable.
        /// </summary>
        /// <param name="key">string; The string identifying the ConnectionString in the appsettings.json file</param>
        /// <returns></returns>
        private string setConnectionString(string key, IConfigurationRoot config)
        {
            string prefix = nameof(setConnectionString) + Constants.FNSUFFIX;

            if (string.IsNullOrWhiteSpace(key))
            {
                _logger.LogWarning(prefix + "Passed in key argument was empty.");
                return string.Empty;
            }

            string connStrRaw = config.GetConnectionString(key);            
            
            if (string.IsNullOrWhiteSpace(connStrRaw))
            {
                _logger.LogWarning(prefix + $"ConnectionString for key [{key}] was empty.");
                return "";
            }

            connStrRaw = connStrRaw.TrimEnd(';'); // Remove trailing semis if they exist

            string targetKey = "PasswordEnvVar"; 
            string targetVal = ""; 
            string[] arrConnStrRaw = connStrRaw.Split(';');
            List<string> listConnStrRawClean = new List<string>();
            foreach (string kvp in arrConnStrRaw)
            {
                string[] arrKvp = kvp.Split('=');
                if (arrKvp.Count() == 2)
                {
                    if (arrKvp[0] == targetKey)
                    {
                        // If this is the PasswordEnvVar variable, 
                        // get the key, and do not add to clean list.
                        targetVal = arrKvp[1];
                    }
                    else
                    {
                        // Pass straight through to the clean list
                        listConnStrRawClean.Add(kvp);
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(targetVal))
            {
                _logger.LogWarning(prefix + $"PasswordEnvVar setting in ConnectionString for key [{key}] was empty.");
                return connStrRaw;
            }

            string password = config.GetSection(targetVal).Value;

            if (string.IsNullOrWhiteSpace(password))
            {
                _logger.LogWarning(prefix + $"Environment Variable [{targetVal}] was empty.");
            }

            listConnStrRawClean.Add("Password=" + password);
            return string.Join(";", listConnStrRawClean);
        }
    }
    */
}
