using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.Diagnostics; // Stopwatch
using System.Data.Common; // DbCommand
using System.Data; // CommandType

namespace NZ01
{

    public class BaseDAL : IDisposable
    {
        /////////////////// 
        // STATIC MEMBERS

        public static readonly string UNICODE_PREFIX = "N";



        ///////////////////// 
        // INSTANCE MEMBERS

        public UInt32 StandardFieldSize { get; set; } = 255; // Database most common text field size 
        public string ConnStr { get; set; }
        public UInt32 QueryPerformanceWarningLimitMillis { get; set; } = 2000; // Milliseconds to allow before warning of poor performance
        public bool UseQuotedDates { get; set; } = true;

        private bool _disposed = false;
        private WrappedConnection _wrappedconn = null;




        public BaseDAL(string connectionString)
        {
            _wrappedconn = new WrappedConnection(connectionString);
        }





        /////////////////////
        // MEMBER FUNCTIONS  


        protected virtual void Dispose(bool bDisposing)
        {
            if (_disposed)
                return;

            // Dispose(true) should clean up native and managed resources.
            // Dispose(false) should clean up only native resources.
            // This class' only resource is a WrappedConnection.

            // Clean up native resources:
            // NONE

            if (bDisposing)
            {
                // Clean up managed resources:
                if (_wrappedconn != null)
                {
                    _wrappedconn.Dispose();
                }
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public bool IsOpen()
        {
            if (_wrappedconn != null)
                return _wrappedconn.IsOpen();

            return false;
        }

        public WrappedConnection GetConnection()
        {
            return _wrappedconn;
        }

        public DbCommand CreateCmd(string sql)
        {
            if (_wrappedconn == null)
                return null;

            DbCommand cmd = _wrappedconn.Conn.CreateCommand();
            cmd.CommandText = sql;
            cmd.CommandType = CommandType.Text;
            return cmd;
        }



        public DbCommand CreateTransCmd()
        {
            if (_wrappedconn == null)
                return null;

            DbCommand cmd = _wrappedconn.Conn.CreateCommand();
            cmd.CommandType = CommandType.Text;
            cmd.Transaction = _wrappedconn.Conn.BeginTransaction();
            return cmd;
        }

        public bool ExecNonQuery(string sql, string prefix = "")
        {
            if (string.IsNullOrWhiteSpace(prefix)) prefix = nameof(ExecNonQuery) + Constants.FNSUFFIX;

            if (_wrappedconn == null) { throw new Exception("The wrapped connection was null."); }
            if (string.IsNullOrWhiteSpace(sql)) { throw new ArgumentException("The argument sql string was null, white space or empty."); }

            Log4NetAsyncLog.Info(prefix + $"Issuing SQL Command [{sql}]");

            Stopwatch stopwatch = new Stopwatch();
            bool result = false;

            try
            {
                using (DbCommand cmd = CreateCmd(sql))
                {
                    stopwatch.Start();
                    if (cmd != null)
                    {
                        cmd.ExecuteNonQuery();
                        result = true;
                    }
                }
            }
            catch 
            {
                throw;
            }
            finally
            {
                stopwatch.Stop();
                if (stopwatch.ElapsedMilliseconds > QueryPerformanceWarningLimitMillis)
                {
                    Log4NetAsyncLog.Warn(prefix + 
                        $"Query elapsed time {stopwatch.ElapsedMilliseconds}ms exceeded limit {QueryPerformanceWarningLimitMillis}ms for SQL command:[{sql}]");
                }
            }

            return result;
        }

        public bool ExecNonQueryTransaction(IEnumerable<string> sqlNonQueries, string prefix)
        {
            if (string.IsNullOrWhiteSpace(prefix)) prefix = nameof(ExecNonQuery) + Constants.FNSUFFIX;

            if (_wrappedconn == null) { throw new Exception("The wrapped connection was null."); }

            if (!sqlNonQueries.Any()) { throw new ArgumentException("No query strings were provided in the sqlNonQueries collection."); }

            Stopwatch stopwatch = new Stopwatch();
            bool result = true;

            try
            {
                using (DbCommand cmd = CreateTransCmd())
                {
                    if (cmd != null)
                    {
                        try
                        {
                            // Loop the NonQuery sql strings attempting to execute them
                            int i = 0;
                            int length = sqlNonQueries.Count();
                            stopwatch.Start();
                            foreach (string sql in sqlNonQueries)
                            {
                                ++i;
                                cmd.CommandText = sql;

                                string msg = string.Format("Issuing SQL command [transactional] ({0} of {1}): [{2}]", i, length, sql);
                                Log4NetAsyncLog.Info(prefix + msg);

                                cmd.ExecuteNonQuery();
                            }

                            // Execute as a transaction
                            cmd.Transaction.Commit();
                        }
                        catch (Exception ex1)
                        {
                            string msg1 = string.Format("Transaction failed; Rollback will be attempted; Error:{0}", ex1.Message);
                            Log4NetAsyncLog.Error(prefix + msg1);

                            try
                            {
                                cmd.Transaction.Rollback();
                            }
                            catch (Exception ex2)
                            {
                                string msg2 = string.Format("Transaction rollback failed, transaction was not active; Error:{0}", ex2.Message);
                                Log4NetAsyncLog.Error(prefix + msg2);
                                throw;
                            }

                            throw;
                        }
                        finally
                        {
                            stopwatch.Stop();
                            Int64 elapsedMillis = stopwatch.ElapsedMilliseconds;

                            Log4NetAsyncLog.Debug(prefix + string.Format("Transaction elapsed time: {0}ms", elapsedMillis));

                            if (stopwatch.ElapsedMilliseconds > QueryPerformanceWarningLimitMillis)
                            {
                                string msg = string.Format("Transaction elapsed time {0}ms exceeded warning limit {1}ms;", elapsedMillis, QueryPerformanceWarningLimitMillis);
                                Log4NetAsyncLog.Warn(prefix + msg);
                            }
                        }
                    } 
                    else
                    {
                        throw new Exception("CreateTransCmd() failed to return a valid command object.");
                    } // end of "if (cmd != null)"
                }
            }
            catch
            {
                throw;
            }

            return result;
        }




        //////////////////
        // SQL FUNCTIONS

        public bool IsSqlSanitizeValid(string s, int maxsize = -1, bool unicode = true, bool tolerateForwardSlash = false)
        {
            if (maxsize == -1) maxsize = (int)StandardFieldSize;
            //if (string.IsNullOrWhiteSpace(s)) return false;

            string sSanitized = s.SqlSanitize(tolerateForwardSlash).Truncate(maxsize, false);

            return string.Equals(s, sSanitized);
        }

        public string Sqlize(string s, int maxsize = -1, bool unicode = true, bool tolerateForwardSlash = false)
        {
            if (maxsize == -1) maxsize = (int)StandardFieldSize;
            if (string.IsNullOrWhiteSpace(s))
                return "NULL";
            else
                return (unicode ? UNICODE_PREFIX : "") + "'" + (s.SqlSanitize(tolerateForwardSlash)).Truncate(maxsize, false) + "'";
        }

        public string SqlizeNoSanitize(string s, int maxsize = -1, bool unicode = true)
        {
            if (maxsize == -1) maxsize = (int)StandardFieldSize;
            if (string.IsNullOrWhiteSpace(s))
                return "NULL";
            else
                return (unicode ? UNICODE_PREFIX : "") + "'" + s.Truncate(maxsize, false) + "'";
        }

        public static int Sqlize(bool flag)
        {
            return (flag ? 1 : 0);
        }

        public static string Sqlize(decimal d)
        {
            if (d == decimal.MaxValue || d == decimal.MinValue)
                return "NULL";
            else
                return d.ToString();
        }

        public string Sqlize(DateTime dt)
        {
            if (dt == DateTime.MinValue || dt == DateTime.MaxValue)
                return "NULL";
            else
            {
                string quote = UseQuotedDates ? "'" : "";                
                return (quote + dt.ToString(Constants.DATETIMEFORMAT) + quote);
            }
        }

        public string GetDate()
        {
            string quote = UseQuotedDates ? "'" : "";
            return quote + DateTime.UtcNow.ToString(Constants.DATETIMEFORMAT) + quote;
        }


    }

}
