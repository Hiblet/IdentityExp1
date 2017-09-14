using System;
using System.Linq;

using System.Text; // Encoding
using System.Text.RegularExpressions; // Regex

namespace NZ01
{
    public static class ExtensionsString
    {

        //////////////////////
        // STRING EXTENSIONS
        //

        private static readonly Regex _RegexWhitespace = new Regex(@"\s+");


        /// <summary>
        /// Check if a string contains text; Defaults to ignoring case, but can be over-ridden
        /// </summary>
        /// <param name="source"></param>
        /// <param name="toCheck"></param>
        /// <param name="comp"></param>
        /// <returns></returns>
        public static bool ContainsCaseInsensitive(this string source, string toCheck, StringComparison comp = StringComparison.OrdinalIgnoreCase)
        {
            return source.IndexOf(toCheck, comp) >= 0;
        }


        /// <summary>
        /// Get a string to report if it is Numeric in bases Dec/Hex/Bin/Oct
        /// </summary>
        /// <param name="s">string</param>
        /// <returns>bool; true if numeric</returns>
        /// <remarks>
        /// This is taken from PHP's isNumeric function.
        /// Ref: http://php.net/manual/en/function.is-numeric.php
        /// Source: http://stackoverflow.com/questions/894263/how-to-identify-if-a-string-is-a-number (see JDB answer)
        /// </remarks>
        public static bool IsNumeric(this String s)
        {
            return numericRegex.IsMatch(s);
        }


        /// <summary>
        /// Regex for IsNumeric
        /// </summary>
        static readonly Regex numericRegex =
            new Regex("^(" +
            /*Hex*/ @"0x[0-9a-f]+" + "|" +
            /*Bin*/ @"0b[01]+" + "|" +
            /*Oct*/ @"0[0-7]*" + "|" +
            /*Dec*/ @"((?!0)|[-+]|(?=0+\.))(\d*\.)?\d+(e\d+)?" + ")$");


        /// <summary>
        /// Get a string to report if it is alphanumeric only, no spaces
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static bool IsAlphanumeric(this String s)
        { return alphanumericRegex.IsMatch(s); }

        static readonly Regex alphanumericRegex = new Regex("^[a-zA-Z0-9]*$");


        /// <summary>
        /// Get a string to report if it is alphanumeric only, but with certain allowed characters.
        /// </summary>
        /// <param name="s"></param>
        /// <param name="sValidChars">string; String of allowed non-alphanumeric characters</param>
        /// <returns></returns>
        public static bool IsAlphanumericPlus(this String s, string sValidChars)
        {
            string sAllowed =
                Constants.ALPHAUPPER +
                Constants.ALPHALOWER +
                Constants.NUMERIC +
                sValidChars;

            bool containsInvalidChars = false;
            foreach (char c in s)
            {
                if (sAllowed.IndexOf(c) == -1)
                {
                    // c is not in sAllowed, therefore it is invalid
                    containsInvalidChars = true;
                    break;
                }
            }

            return !containsInvalidChars;
        }




        /// <summary>
        /// Return boolean true if the string is a common representation of true.
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static bool IsTrue(this String s)
        {
            if (s.Equals("Y", StringComparison.OrdinalIgnoreCase)) return true;
            if (s.Equals("1", StringComparison.OrdinalIgnoreCase)) return true;
            if (s.Equals("TRUE", StringComparison.OrdinalIgnoreCase)) return true;

            return false;
        }


        public static string ReplaceFirst(this string text, string textSearch, string textReplace)
        {
            if (string.IsNullOrWhiteSpace(text)) return text;
            if (string.IsNullOrWhiteSpace(textSearch)) return text;
            if (textReplace == null) return text;

            Regex rx = new Regex(textSearch);
            return rx.Replace(text, textReplace, 1);
        }

        public static string ReplaceWhitespace(this string text, string textReplace = "")
        {
            return _RegexWhitespace.Replace(text, textReplace);
        }

        /// <summary>
        /// Get a string to tell you if it is ASCII or not.
        /// </summary>
        /// <param name="s"></param>
        /// <returns>bool</returns>
        /// <remarks>
        /// XML using in XML.Linq cannot handle Unicode.
        /// The elements in the Limit spec are symbols, which are system generated ASCII codes,
        /// at least at time of writing.  The file should only have Ascii elements, so this 
        /// fn can be used to police that rule.
        /// </remarks>
        public static bool IsAscii(this String s)
        {
            string sOut = Encoding.ASCII.GetString(Encoding.ASCII.GetBytes(s));
            return (sOut == s);
        }

        /// <summary>
        /// Remove any characters from a string that are not in the allowedChars string
        /// </summary>
        /// <param name="s">string; Input string</param>
        /// <param name="allowedChars">string; All allowed characters</param>
        /// <returns>string; The input string devoid of any characters not in the allowedChars string</returns>
        /// <remarks>
        /// This is case sensitive, so if you want to allow chars 'a' and 'A' include both in the allowed chars string.
        /// </remarks>
        public static string Filter(this String s, string allowedChars)
        {
            string sFiltered = string.Empty;

            foreach (char c in s)
            {
                if (allowedChars.Contains(c))
                    sFiltered += c;
            }

            return sFiltered;
        }

        /// <summary>
        /// Truncate a string if it exceeds a given length, and indicate truncation by adding an elipsis
        /// </summary>
        /// <param name="s">string;</param>
        /// <param name="maxLength">int; The maximum allowed length of the string</param>
        /// <param name="ellipsis">bool; Flag to indicate if an ellipsis should be used to show truncation</param>
        /// <returns>string; Truncated string with optional ellipsis</returns>
        public static string Truncate(this String s, int maxLength, bool ellipsis)
        {
            if (null == s)
                return s;

            if (maxLength <= 4)
                return s;

            if (s.Length > maxLength)
            {
                if (ellipsis)
                    return s.Substring(0, maxLength - 3) + "...";
                else
                    return s.Substring(0, maxLength);
            }
            else
                return s;
        }

        /// <summary>
        /// Get the ASCII representation of a string
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        /// <remarks></remarks>
        public static string ToAscii(this String s)
        {
            return Encoding.ASCII.GetString(Encoding.ASCII.GetBytes(s));
        }



        // V2 - Conditional
        public static string SqlSanitize(this String stringValue, bool bTolerateForwardSlash = false)
        {
            if (null == stringValue)
                return stringValue;

            stringValue = stringValue.regexReplace("-{2,}", "-")            // Transforms multiple hyphens into single hyphens, used to comment in sql scripts
                        .regexReplace(
                            @"(;|\s)(exec|execute|select|insert|update|delete|create|alter|drop|rename|truncate|backup|restore|error)\s",
                            "-",
                            RegexOptions.IgnoreCase);

            if (bTolerateForwardSlash)
                return stringValue.regexReplace(@"['*]+", string.Empty);    // Allow forward slash, remove asterisk and single quote
            else
                return stringValue.regexReplace(@"['*/]+", string.Empty);   // Remove / and * used also to comment in sql scripts - Hibbert: added single quote
        }

        private static string regexReplace(this string stringValue, string matchPattern, string toReplaceWith)
        {
            return Regex.Replace(stringValue, matchPattern, toReplaceWith);
        }

        private static string regexReplace(this string stringValue, string matchPattern, string toReplaceWith, RegexOptions regexOptions)
        {
            return Regex.Replace(stringValue, matchPattern, toReplaceWith, regexOptions);
        }

    } // end of Extensions_String

} // end of namespace NZ01