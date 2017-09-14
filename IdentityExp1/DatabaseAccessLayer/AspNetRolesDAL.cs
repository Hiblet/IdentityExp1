using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.Text; // StringBuilder
using System.Data.Common; // DbCommand, DbDataReader

namespace NZ01
{
    public class AspNetRolesDAL : BaseDAL
    {
        public readonly string _table = "AspNetRoles";

        private readonly int MAXSIZE_ROLENAME = 255;


        // Ctor
        public AspNetRolesDAL(string connStr) : base(connStr) { }


        public ApplicationRole SelectByRoleId(string roleId) { return SelectByColumnValue("Id", roleId); }
        public ApplicationRole SelectByRoleName(string normalizedRoleName) { return SelectByColumnValue("NormalizedName", normalizedRoleName); }

        public ApplicationRole SelectByColumnValue(string column, string colValue)
        {
            string prefix = nameof(SelectByColumnValue) + Constants.FNSUFFIX;

            if (string.IsNullOrWhiteSpace(colValue)) throw new ArgumentNullException(nameof(colValue));
            if (string.IsNullOrWhiteSpace(column)) throw new ArgumentNullException(nameof(column));

            List<string> cols = new List<string>();
            cols.Add("Id");
            cols.Add("ConcurrencyStamp");
            cols.Add("Name");
            string csvCols = string.Join(",", cols);

            string sql = $"SELECT {csvCols} FROM {_table} WHERE {column}={SqlizeNoSanitize(colValue)};";

            int countRecord = 0;
            List<ApplicationRole> loadedRecords = new List<ApplicationRole>();

            try
            {
                using (DbCommand cmd = CreateCmd(sql))
                using (DbDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        ++countRecord;

                        string id = "";
                        string concurrencyStamp = "";
                        string name = "";

                        if (reader["Id"] != DBNull.Value) id = (string)reader["Id"];
                        if (reader["ConcurrencyStamp"] != DBNull.Value) concurrencyStamp = (string)reader["ConcurrencyStamp"];
                        if (reader["Name"] != DBNull.Value) name = (string)reader["Name"];

                        ApplicationRole appRole = new ApplicationRole
                        {
                            RoleId = id,
                            ConcurrencyStamp = concurrencyStamp,
                            RoleName = name
                        };

                        loadedRecords.Add(appRole);

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


        public void Insert(ApplicationRole role)
        {
            string prefix = nameof(Insert) + Constants.FNSUFFIX;

            if (!IsSqlSanitizeValid(role.RoleName, MAXSIZE_ROLENAME))
                throw new ArgumentException($"Role name [{role.RoleName}] does not pass SQL Sanitization; Choose alternative name for role.");

            StringBuilder sb = new StringBuilder();

            sb.Append($"INSERT INTO {_table} (");

            sb.Append("UpdateTimestamp,");
            sb.Append("Id,");
            sb.Append("Name,");
            sb.Append("NormalizedName,");
            sb.Append("ConcurrencyStamp");

            sb.Append(") VALUES (");

            sb.Append($"{GetDate()},");
            sb.Append($"{SqlizeNoSanitize(role.RoleId)},");
            sb.Append($"{Sqlize(role.RoleName)},");
            sb.Append($"{Sqlize(role.RoleNameNormalized)},");
            sb.Append($"{SqlizeNoSanitize(role.ConcurrencyStamp)}");

            sb.Append(");");

            ExecNonQuery(sb.ToString(), prefix);
        }


        public bool Update(ApplicationRole role)
        {
            string prefix = nameof(Update) + Constants.FNSUFFIX;

            if (!IsSqlSanitizeValid(role.RoleName, MAXSIZE_ROLENAME))
                throw new ArgumentException($"Role name [{role.RoleName}] does not pass SQL Sanitization; Choose alternative name for role.");

            StringBuilder sb = new StringBuilder();

            sb.Append($"UPDATE {_table} SET UpdateTimestamp={GetDate()},");

            sb.Append($"ConcurrencyStamp={SqlizeNoSanitize(role.ConcurrencyStamp)},");
            sb.Append($"Name={Sqlize(role.RoleName)},");
            sb.Append($"NormalizedName={Sqlize(role.RoleNameNormalized)} ");

            sb.Append($"WHERE Id={SqlizeNoSanitize(role.RoleId)};");

            return ExecNonQuery(sb.ToString(), prefix);
        }

        public IEnumerable<string> SelectRoleNamesByRoleId(IEnumerable<string> roleIDs)
        {
            string prefix = nameof(SelectRoleNamesByRoleId) + Constants.FNSUFFIX;

            if (!roleIDs.Any()) return new List<string>(); // No IDs, no roles to return.

            List<string> sqlizedRoleIDs = new List<string>();
            foreach (string roleID in roleIDs)            
                sqlizedRoleIDs.Add(Sqlize(roleID));
            
            string sql = $"SELECT Name FROM {_table} WHERE Id IN ({string.Join(",",sqlizedRoleIDs)});";

            int countRecord = 0;
            List<string> loadedRecords = new List<string>();

            try
            {
                using (DbCommand cmd = CreateCmd(sql))
                using (DbDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        ++countRecord;

                        string name = "";

                        if (reader["Name"] != DBNull.Value) name = (string)reader["Name"];

                        if (!string.IsNullOrWhiteSpace(name))
                            loadedRecords.Add(name);

                    } // end of while...

                } // end of using...
            }
            catch (Exception ex)
            {
                string msg = $"Exception=[{ex.ToString()}]";
                Log4NetAsyncLog.Error(prefix + msg);
            }

            return loadedRecords;
        }
    }
}
