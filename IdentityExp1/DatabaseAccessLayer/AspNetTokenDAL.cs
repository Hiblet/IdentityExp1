using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.Text; // StringBuilder
using System.Data.Common; // DbCommand, DbDataReader

namespace NZ01
{
    public class AspNetTokensDAL : BaseDAL
    {
        public readonly string _table = "AspNetTokens";

        private readonly int MAXSIZE_USERNAME = 450;

        // Ctor
        public AspNetTokensDAL(string connStr) : base(connStr) { }


        public ApplicationJwtRefreshToken SelectByGuid(string guid) { return SelectByColumnValue("Guid", guid); }

        public ApplicationJwtRefreshToken SelectByColumnValue(string column, string colValue)
        {
            string prefix = nameof(SelectByColumnValue) + Constants.FNSUFFIX;

            if (string.IsNullOrWhiteSpace(colValue)) throw new ArgumentNullException(nameof(colValue));
            if (string.IsNullOrWhiteSpace(column)) throw new ArgumentNullException(nameof(column));

            List<string> cols = new List<string>();
            cols.Add("Name");
            cols.Add("IP");
            cols.Add("Guid");
            string csvCols = string.Join(",", cols);

            string sql = $"SELECT {csvCols} FROM {_table} WHERE {column}={SqlizeNoSanitize(colValue)};";

            int countRecord = 0;
            List<ApplicationJwtRefreshToken> loadedRecords = new List<ApplicationJwtRefreshToken>();

            try
            {
                using (DbCommand cmd = CreateCmd(sql))
                using (DbDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        ++countRecord;

                        string ip = "";
                        string guid = "";
                        string name = "";

                        if (reader["IP"] != DBNull.Value) ip = (string)reader["IP"];
                        if (reader["Guid"] != DBNull.Value) guid = (string)reader["Guid"];
                        if (reader["Name"] != DBNull.Value) name = (string)reader["Name"];

                        ApplicationJwtRefreshToken token = new ApplicationJwtRefreshToken
                        {
                            Name = name,
                            Guid = guid,
                            IP = ip
                        };

                        loadedRecords.Add(token);

                    } // end of while...

                } // end of using...
            }
            catch (Exception ex)
            {
                string msg = $"Failed to find record where {column}={SqlizeNoSanitize(colValue)}; Exception=[{ex.ToString()}]";
                Log4NetAsyncLog.Error(prefix + msg);
            }

            int countLoadedRecords = loadedRecords.Count();

            if (countLoadedRecords == 1)
                return loadedRecords.First();

            if (countLoadedRecords > 1)
            {
                string msg = $"More than one record exists where {column}={SqlizeNoSanitize(colValue)}; This should never happen.";
                Log4NetAsyncLog.Error(prefix + msg);
                return loadedRecords.FirstOrDefault();
            }

            // Zero case
            return null;
        }

        public void Insert(ApplicationJwtRefreshToken token)
        {
            string prefix = nameof(Insert) + Constants.FNSUFFIX;

            if (!IsSqlSanitizeValid(token.Name, MAXSIZE_USERNAME))
                throw new ArgumentException($"User name [{token.Name}] does not pass SQL Sanitization.");

            StringBuilder sb = new StringBuilder();

            sb.Append($"INSERT INTO {_table} (");

            sb.Append("UpdateTimestamp,");
            sb.Append("IP,");
            sb.Append("Name,");
            sb.Append("Guid");

            sb.Append(") VALUES (");

            sb.Append($"{GetDate()},");
            sb.Append($"{SqlizeNoSanitize(token.IP)},");
            sb.Append($"{Sqlize(token.Name)},");
            sb.Append($"{SqlizeNoSanitize(token.Guid)}");

            sb.Append(");");

            ExecNonQuery(sb.ToString(), prefix);
        }

        public void Delete(string guid)
        {
            string prefix = nameof(Delete) + Constants.FNSUFFIX;

            string sql = $"DELETE FROM {_table} WHERE Guid={SqlizeNoSanitize(guid)};";

            ExecNonQuery(sql, prefix);
        }

        // THIS SHOULD NOT BE BEING CALLED - REMOVE?
        /*
        public bool Update(ApplicationJwtRefreshToken token)
        {
            string prefix = nameof(Update) + Constants.FNSUFFIX;

            if (!IsSqlSanitizeValid(token.Name, MAXSIZE_USERNAME))
                throw new ArgumentException($"User name [{token.Name}] does not pass SQL Sanitization.");

            StringBuilder sb = new StringBuilder();

            sb.Append($"UPDATE {_table} SET UpdateTimestamp={GetDate()},");

            sb.Append($"Name={Sqlize(token.Name)},");
            sb.Append($"IP={SqlizeNoSanitize(token.IP)} ");

            sb.Append($"WHERE Guid={SqlizeNoSanitize(token.Guid)};");

            return ExecNonQuery(sb.ToString(), prefix);
        }
        */

    }
}
