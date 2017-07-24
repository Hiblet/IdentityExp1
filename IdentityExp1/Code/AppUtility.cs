using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Reflection;

using Microsoft.AspNetCore.Http; // HttpContext
using Microsoft.Extensions.Primitives; // StringValues

namespace NZ01
{
    public class AppUtility
    {
        ///////////////////////////////////////////////////////////////////////////
        // HTTP

        /// <summary>
        /// Examine the request context to get the remote connected IP address.
        /// Optionally trust the X-Forwarded-For Header
        /// </summary>
        /// <param name="context">HttpContext; Expected to be the Request context</param>
        /// <param name="tryUseXForwardHeader">bool; Defaulting to true; Option to use the X-Forwarded-For header value</param>
        /// <returns>
        /// string; 
        /// If successful, the string is the IP address of the requestor as defined in the request context;
        /// If not, string will be the empty string.
        /// </returns>
        /// <remarks>
        /// https://en.wikipedia.org/wiki/X-Forwarded-For
        /// Ref: https://stackoverflow.com/questions/28664686/how-do-i-get-client-ip-address-in-asp-net-core
        /// Credit: StackOverflow user "crokusek"
        /// </remarks>

        public static string GetRequestIP(HttpContext context, bool tryUseXForwardHeader = true )
        {
            string ip = "";

            if (context == null) return "";

            if (tryUseXForwardHeader)
            {
                string xForwardHeader = GetHeaderValueAs<string>("X-Forwarded-For", context);
                List<string> xForwardHeaderValues = SplitCsv(xForwardHeader);
                ip = xForwardHeaderValues.FirstOrDefault();
            }

            if (string.IsNullOrWhiteSpace(ip) && context.Connection?.RemoteIpAddress != null)
                ip = context.Connection.RemoteIpAddress.ToString();

            if (string.IsNullOrWhiteSpace(ip))
                ip = GetHeaderValueAs<string>("REMOTE_ADDR", context);

            return ip;
        }

        public static T GetHeaderValueAs<T>(string headerName, HttpContext context)
        {
            StringValues values;

            if (context?.Request?.Headers?.TryGetValue(headerName, out values) ?? false)
            {
                string rawValues = values.ToString();   // writes out as Csv when there are multiple.

                if (!string.IsNullOrWhiteSpace(rawValues))
                    return (T)Convert.ChangeType(values.ToString(), typeof(T));
            }

            return default(T);
        }

        public static List<string> SplitCsv(string csvList, bool nullOrWhitespaceInputReturnsNull = false)
        {
            if (string.IsNullOrWhiteSpace(csvList))
                return nullOrWhitespaceInputReturnsNull ? null : new List<string>();

            return csvList
                .TrimEnd(',')
                .Split(',')
                .AsEnumerable<string>()
                .Select(s => s.Trim())
                .ToList();
        }

        //
        ///////////////////////////////////////////////////////////////////////////


        ///////////////////////////////////////////////////////////////////////////
        // HANDLING UNKNOWN OBJECTS
        //

        /// <summary>
        /// Test an unknown object and see if it has a property; Uses reflection.
        /// </summary>
        /// <param name="obj">Object; The mysterious object to test</param>
        /// <param name="targetProperty">String; The property to look for</param>
        /// <returns>bool; True implies the property exists;</returns>
        public static bool PropertyExists(object obj, string targetProperty)
        {
            //return ((Type)obj.GetType()).GetProperties().Any(x => x.Name.Equals(property)); // Linq variant
            PropertyInfo[] properties = ((Type)obj.GetType()).GetProperties();
            foreach (PropertyInfo property in properties)
            {
                if (string.Equals(property.Name, targetProperty, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Fail
            return false;
        }

        /// <summary>
        /// Test an unknown object and see if it has a property that starts with the given string; Uses reflection.
        /// </summary>
        /// <param name="obj">Object; The mysterious object to test</param>
        /// <param name="targetPropertyStem">String; The starting part of the property to look</param>
        /// <returns></returns>
        public static bool HasPropertyStartingWith(object obj, string targetPropertyStem)
        {
            //return ((Type)obj.GetType()).GetProperties().Any(x => x.Name.StartsWith(propertyStem)); // Linq 
            PropertyInfo[] properties = ((Type)obj.GetType()).GetProperties();
            foreach (PropertyInfo property in properties)
            {
                if (property.Name.StartsWith(targetPropertyStem, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Fail
            return false;
        }

        public static string GetPropertyNameThatStartsWith(object obj, string propertyStem)
        {
            PropertyInfo[] properties = ((Type)obj.GetType()).GetProperties();
            foreach (PropertyInfo property in properties)
            {
                string propertyName = property.Name;
                if (property.Name.StartsWith(propertyStem, StringComparison.OrdinalIgnoreCase))
                    return property.Name;
            }

            // Fail
            return "";
        }

        public static string GetDynamicPropertyValueAsString(dynamic obj, string property, string fail = "")
        {
            var jObj = obj as Newtonsoft.Json.Linq.JObject;

            if (jObj == null)
                return fail;

            if (jObj[property] == null)
                return fail;
            else
                return jObj[property].ToString();
        }

        public static Int64 GetDynamicPropertyValueAsInt64(dynamic obj, string property, Int64 fail = Int64.MinValue)
        {
            var jObj = obj as Newtonsoft.Json.Linq.JObject;

            if (jObj == null)
                return fail;

            if (jObj[property] == null)
                return fail;

            Int64? returnValue = (Int64)jObj[property];

            if (returnValue == null)
                return fail;
            else
                return (Int64)returnValue;
        }

        public static bool GetDynamicPropertyValueAsBool(dynamic obj, string property, bool fail = false)
        {
            var jObj = obj as Newtonsoft.Json.Linq.JObject;

            if (jObj == null)
                return fail;

            if (jObj[property] == null)
                return fail;

            bool? returnValue = (bool)jObj[property];

            if (returnValue == null)
                return fail;
            else
                return (bool)returnValue;
        }

        //
        ///////////////////////////////////////////////////////////////////////////

    }
}
