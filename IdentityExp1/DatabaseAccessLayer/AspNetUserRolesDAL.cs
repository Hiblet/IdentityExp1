using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.Text; // StringBuilder
using System.Data.Common; // DbCommand, DbDataReader


namespace NZ01
{
    public class AspNetUserRolesDAL : BaseDAL
    {
        public readonly string _table = "AspNetUserRoles";

        // Ctor
        public AspNetUserRolesDAL(string connStr) : base(connStr) { }

        public IEnumerable<string> SelectRolesForUser(string userId)
        {
            string prefix = nameof(SelectRolesForUser) + Constants.FNSUFFIX;

            if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentNullException(nameof(userId));

            string sql = $"SELECT RoleId FROM {_table} WHERE UserId={SqlizeNoSanitize(userId)};";

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

                        string roleID = "";

                        if (reader["RoleId"] != DBNull.Value) roleID = (string)reader["RoleId"];

                        if (!string.IsNullOrWhiteSpace(roleID))                     
                            loadedRecords.Add(roleID);
                        
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

        public IEnumerable<string> SelectUsersInRole(String roleId)
        {
            string prefix = nameof(SelectUsersInRole) + Constants.FNSUFFIX;

            if (string.IsNullOrWhiteSpace(roleId)) throw new ArgumentNullException(nameof(roleId));

            string sql = $"SELECT UserId FROM {_table} WHERE RoleId={SqlizeNoSanitize(roleId)};";

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

                        string userID = "";

                        if (reader["UserId"] != DBNull.Value) userID = (string)reader["UserId"];

                        if (!string.IsNullOrWhiteSpace(userID))
                            loadedRecords.Add(userID);

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

        public void Insert(string userID, string roleID)
        {
            string prefix = nameof(Insert) + Constants.FNSUFFIX;

            string sql = $"INSERT INTO {_table} (UserId,RoleId) VALUES ({SqlizeNoSanitize(userID)},{SqlizeNoSanitize(roleID)});";

            ExecNonQuery(sql, prefix);
        }

        public void Delete(string userID, string roleID)
        {
            string prefix = nameof(Delete) + Constants.FNSUFFIX;

            string sql = $"DELETE FROM {_table} WHERE UserId={SqlizeNoSanitize(userID)} AND RoleId={SqlizeNoSanitize(roleID)};";

            ExecNonQuery(sql, prefix);
        }
    }
}
