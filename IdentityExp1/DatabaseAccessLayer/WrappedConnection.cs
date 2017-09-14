using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.Data.Common; 
using System.Data; // ConnectionState
using System.Data.SqlClient; // SqlConnection



namespace NZ01
{
    public class WrappedConnection : IDisposable
    {
        ////////////
        // MEMBERS

        private bool bDisposed = false;
        private DbConnection conn = null;


        // CTOR/DTOR
        public WrappedConnection(string connString)
        {
            string prefix = nameof(WrappedConnection) + Constants.FNSUFFIX;

            //conn = DbAccess.DbUtils.ConnectionFactory.CreateConn(connString);
            conn = new SqlConnection(connString);

            if (conn == null)
            {
                Log4NetAsyncLog.Error(prefix + $"Failed to get connection to database using connection string [{connString}]");
                return;
            }

            if (conn.State != ConnectionState.Open)            
                conn.Open();            
        }

        ~WrappedConnection()
        {
            // Does not drop connection
            Dispose(false);
        }

        // PROPERTIES
        public DbConnection Conn
        {
            get { return conn; }
        }

        // METHODS
        public void Dispose()
        {
            // User triggers a manual cleanup
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public bool IsOpen()
        {
            if (conn != null)
                return (conn.State == ConnectionState.Open);
            else
                return false;
        }


        protected virtual void Dispose(bool bDisposing)
        {
            var prefix = "Dispose(bool) - ";
            string msg = "";

            // Do not dispose twice.
            if (this.bDisposed)
                return;

            if (bDisposing)
            {
                // Manual disposal via explicit call in code

                //msg = "This function has been called from code: EXPLICIT";
                //logger.Debug(prefix + msg);

                if (conn == null)
                {
                    //msg = "The connection is null;  Cannot close connection.";
                    //logger.Warn(prefix + msg);
                }
                else
                {
                    //msg = "The connection is not null; Attempting to close connection.";
                    //logger.Debug(prefix + msg);

                    try
                    {
                        conn.Close();

                        //msg = "The connection has been successfully closed.";
                        //logger.Debug(prefix + msg);
                    }
                    catch (Exception ex)
                    {
                        msg = string.Format("Failed to close database connection: {0}", ex.Message);
                        Log4NetAsyncLog.Warn(prefix + msg);
                    }

                } // end of "if (conn == null)"

            }

            bDisposed = true;
        }
    }
}
