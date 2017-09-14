using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NZ01
{
    /// <summary>
    /// Class to store application universal constants.
    /// </summary>
    /// <remarks>
    /// Cross-cutting class to deter magic strings.
    /// </remarks>
    public class Constants
    {
        ///////////////////////////////////////////////////////////////////////
        // APP SPECIFIC

        public static readonly string SECRET_ENV_VAR = "CORE_IDENTITYEXP1";
        public static readonly string GUID_DB = "D"; // Formatting string for GUIDs used in Database

        //
        ///////////////////////////////////////////////////////////////////////


        ///////////////////////////////////////////////////////////////////////
        // GENERIC

        public static readonly string FNSUFFIX = "() - ";
        public static readonly string MIME_JSON = "application/json";

        public static readonly string DATEONLYFORMAT = "yyyy-MM-dd";
        public static readonly string TIMEONLYFORMAT = "HH:mm:ss.fff";
        public static readonly string DATETIMEFORMAT = "yyyy-MM-ddTHH:mm:ss.fff";
        public static readonly string DATETIMEFORMATNOMILLIS = "yyyy-MM-ddTHH:mm:ss";

        public static readonly string ALPHAUPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public static readonly string ALPHALOWER = "abcdefghijklmnopqrstuvwxyz";
        public static readonly string NUMERIC = "0123456789";

        public static readonly int NULL_POSITIVE_INT = -1;
        public static readonly string NULL_STRING = "#NULL#"; // A string value to represent NULL, as empty string is sometimes a valid value    

        //
        ///////////////////////////////////////////////////////////////////////
    }
}