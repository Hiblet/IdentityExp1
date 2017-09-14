using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.Text; // StringBuilder
using System.Data.Common; // DbCommand, DbDataReader


namespace NZ01
{
    public class AspNetUsersDAL : BaseDAL
    {
        public readonly string _table = "AspNetUsers";

        private readonly int MAXSIZE_USERNAME = 450;
        private readonly int MAXSIZE_EMAIL = 450;

        // Ctor
        public AspNetUsersDAL(string connStr) : base(connStr) { }

        public IEnumerable<ApplicationUser> SelectAll()
        {
            string sql = $"SELECT * FROM {_table};";
            return selectSub(sql);
        }

        public IEnumerable<ApplicationUser> SelectByUserIDs(IEnumerable<string> userIDs) { return selectByColumn("Id", userIDs); }

        public ApplicationUser SelectByUserId(string userId)
        {
            string prefix = nameof(SelectByUserId) + Constants.FNSUFFIX;

            IEnumerable<ApplicationUser> users = selectByColumn("Id", new List<string> { userId });

            if (users.Count() == 0) return null;
            if (users.Count() == 1) return users.First();

            // Uh oh, More than one user with this unique ID...
            string msg = $"More than one record exists where UserID is [{userId}]; This should never happen.";
            Log4NetAsyncLog.Error(prefix + msg);
            return users.First();
        }

        public ApplicationUser SelectByUserName(string normalizedUserName)
        {
            string prefix = nameof(SelectByUserName) + Constants.FNSUFFIX;

            IEnumerable<ApplicationUser> users = selectByColumn("NormalizedUserName", new List<string> { normalizedUserName.ToUpper() });

            if (users.Count() == 0) return null;
            if (users.Count() == 1) return users.First();

            // Uh oh, More than one user with this name...
            string msg = $"More than one record exists where UserName is [{normalizedUserName}]; This should never happen.";
            Log4NetAsyncLog.Error(prefix + msg);
            return users.First();
        }

        public ApplicationUser SelectByEmail(string normalizedEmail)
        {
            string prefix = nameof(SelectByEmail) + Constants.FNSUFFIX;

            IEnumerable<ApplicationUser> users = selectByColumn("NormalizedEmail", new List<string> { normalizedEmail.ToUpper() });

            if (users.Count() == 0) return null;
            if (users.Count() == 1) return users.First();

            // Uh oh, More than one user with this name...
            string msg = $"More than one record exists where UserName is [{normalizedEmail}]; This should never happen.";
            Log4NetAsyncLog.Error(prefix + msg);
            return users.First();
        }

        private IEnumerable<ApplicationUser> selectByColumn(string column, IEnumerable<string> colValues)
        {
            string prefix = nameof(selectByColumn) + Constants.FNSUFFIX;

            if (!colValues.Any()) throw new ArgumentException("No column values were provided.");
            if (string.IsNullOrWhiteSpace(column)) throw new ArgumentNullException(nameof(column));

            // Prepare the Where clause for single or multiple values
            string whereOperator = "";
            string whereTarget = "";
            int countColValues = colValues.Count();
            if (countColValues == 1)
            {
                whereOperator = "=";
                whereTarget = SqlizeNoSanitize(colValues.First());
            }
            else
            {
                whereOperator = " IN ";
                List<string> sqlizedColValues = new List<string>();
                foreach (string colValue in colValues)                
                    sqlizedColValues.Add(SqlizeNoSanitize(colValue));
                whereTarget = "(" + string.Join(",", sqlizedColValues) + ")";
            }

            string whereClause = $"WHERE {column}{whereOperator}{whereTarget}";

            List<string> cols = new List<string>();
            cols.Add("Id");
            cols.Add("AccessFailedCount");
            cols.Add("ConcurrencyStamp");
            cols.Add("Email");
            cols.Add("EmailConfirmed");
            cols.Add("LockoutEnabled");
            cols.Add("LockoutEnd");
            cols.Add("PasswordHash");
            cols.Add("PhoneNumber");
            cols.Add("PhoneNumberConfirmed");
            cols.Add("SecurityStamp");
            cols.Add("TwoFactorEnabled");
            cols.Add("UserName");
            cols.Add("Enabled");
            string csvCols = string.Join(",", cols);

            string sql = $"SELECT {csvCols} FROM {_table} {whereClause};";

            return selectSub(sql);
        }


        private IEnumerable<ApplicationUser> selectSub(string sql)
        {
            string prefix = nameof(selectSub) + Constants.FNSUFFIX;

            int countRecord = 0;
            List<ApplicationUser> loadedRecords = new List<ApplicationUser>();

            try
            {
                using (DbCommand cmd = CreateCmd(sql))
                using (DbDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        ++countRecord;

                        string id = "";
                        int accessFailedCount = 0;
                        string concurrencyStamp = "";
                        string email = "";
                        bool emailConfirmed = false;
                        bool lockoutEnabled = false;
                        DateTime lockoutEnd = DateTime.MinValue;
                        string passwordHash = "";
                        string phoneNumber = "";
                        bool phoneNumberConfirmed = false;
                        string securityStamp = "";
                        bool twoFactorEnabled = false;
                        string username = "";
                        bool enabled = false;

                        if (reader["Id"] != DBNull.Value) id = (string)reader["Id"];
                        if (reader["AccessFailedCount"] != DBNull.Value) accessFailedCount = (int)reader["AccessFailedCount"];
                        if (reader["ConcurrencyStamp"] != DBNull.Value) concurrencyStamp = (string)reader["ConcurrencyStamp"];
                        if (reader["Email"] != DBNull.Value) email = (string)reader["Email"];
                        if (reader["EmailConfirmed"] != DBNull.Value) emailConfirmed = (bool)reader["EmailConfirmed"];
                        if (reader["LockoutEnabled"] != DBNull.Value) lockoutEnabled = (bool)reader["LockoutEnabled"];
                        if (reader["LockoutEnd"] != DBNull.Value) lockoutEnd = (DateTime)reader["LockoutEnd"];
                        if (reader["PasswordHash"] != DBNull.Value) passwordHash = (string)reader["PasswordHash"];
                        if (reader["PhoneNumber"] != DBNull.Value) phoneNumber = (string)reader["PhoneNumber"];
                        if (reader["PhoneNumberConfirmed"] != DBNull.Value) phoneNumberConfirmed = (bool)reader["PhoneNumberConfirmed"];
                        if (reader["SecurityStamp"] != DBNull.Value) securityStamp = (string)reader["SecurityStamp"];
                        if (reader["TwoFactorEnabled"] != DBNull.Value) twoFactorEnabled = (bool)reader["TwoFactorEnabled"];
                        if (reader["UserName"] != DBNull.Value) username = (string)reader["UserName"];
                        if (reader["Enabled"] != DBNull.Value) enabled = (bool)reader["Enabled"];

                        ApplicationUser appUser = new ApplicationUser
                        {
                            UserId = id,
                            AccessFailedCount = accessFailedCount,
                            ConcurrencyStamp = concurrencyStamp,
                            Email = email,
                            EmailConfirmed = emailConfirmed,
                            LockoutEnabled = lockoutEnabled,
                            LockoutEnd = lockoutEnd,
                            PasswordHash = passwordHash,
                            PhoneNumber = phoneNumber,
                            PhoneNumberConfirmed = phoneNumberConfirmed,
                            SecurityStamp = securityStamp,
                            TwoFactorEnabled = twoFactorEnabled,
                            UserName = username,
                            Enabled = enabled
                        };

                        loadedRecords.Add(appUser);

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

        public bool Insert(ApplicationUser user)
        {
            string prefix = nameof(Insert) + Constants.FNSUFFIX;

            if (!IsSqlSanitizeValid(user.UserName,MAXSIZE_USERNAME))
                throw new ArgumentException($"Username [{user.UserName}] does not pass SQL Sanitization; Choose alternative username.");

            if (!IsSqlSanitizeValid(user.Email, MAXSIZE_EMAIL))
                throw new ArgumentException($"Email address [{user.Email}] does not pass SQL Sanitization; Check for typo errors, or choose alternative email address.");


            StringBuilder sb = new StringBuilder();

            sb.Append($"INSERT INTO {_table} (");

            sb.Append("UpdateTimestamp,");
            sb.Append("Id,");
            sb.Append("UserName,");
            sb.Append("NormalizedUserName,");
            sb.Append("AccessFailedCount,");
            sb.Append("ConcurrencyStamp,");
            sb.Append("Email,");
            sb.Append("NormalizedEmail,");
            sb.Append("EmailConfirmed,");
            sb.Append("PasswordHash,");
            sb.Append("PhoneNumber,");
            sb.Append("PhoneNumberConfirmed,");
            sb.Append("TwoFactorEnabled,");
            sb.Append("SecurityStamp,");
            sb.Append("Enabled,");
            sb.Append("LockoutEnabled,");
            sb.Append("LockoutEnd");

            sb.Append(") VALUES (");

            sb.Append($"{GetDate()},");
            sb.Append($"{SqlizeNoSanitize(user.UserId)},");
            sb.Append($"{Sqlize(user.UserName)},");
            sb.Append($"{Sqlize(user.UserNameNormalized)},");
            sb.Append($"{user.AccessFailedCount},");
            sb.Append($"{SqlizeNoSanitize(user.ConcurrencyStamp)},");
            sb.Append($"{Sqlize(user.Email)},");
            sb.Append($"{Sqlize(user.EmailNormalized)},");
            sb.Append($"{Sqlize(user.EmailConfirmed)},");
            sb.Append($"{SqlizeNoSanitize(user.PasswordHash)},");
            sb.Append($"{SqlizeNoSanitize(user.PhoneNumber)},");
            sb.Append($"{Sqlize(user.PhoneNumberConfirmed)},");
            sb.Append($"{Sqlize(user.TwoFactorEnabled)},");
            sb.Append($"{SqlizeNoSanitize(user.SecurityStamp)},");
            sb.Append($"{Sqlize(user.Enabled)},");
            sb.Append($"{Sqlize(user.LockoutEnabled)},");
            sb.Append($"{Sqlize(user.LockoutEnd)}");

            sb.Append(");");

            return ExecNonQuery(sb.ToString(), prefix);
        }

        public bool Update(ApplicationUser user)
        {
            string prefix = nameof(Update) + Constants.FNSUFFIX;

            if (!IsSqlSanitizeValid(user.Email, MAXSIZE_EMAIL))
                throw new ArgumentException($"Email address [{user.Email}] does not pass SQL Sanitization; Check for typo errors, or choose alternative email address.");

            // UserName should not change, so do not check and do not write.

            StringBuilder sb = new StringBuilder();

            sb.Append($"UPDATE {_table} SET UpdateTimestamp={GetDate()},");

            sb.Append($"AccessFailedCount={user.AccessFailedCount},");
            sb.Append($"ConcurrencyStamp={SqlizeNoSanitize(user.ConcurrencyStamp)},");
            sb.Append($"Email={Sqlize(user.Email)},");
            sb.Append($"NormalizedEmail={Sqlize(user.EmailNormalized)},");
            sb.Append($"EmailConfirmed={Sqlize(user.EmailConfirmed)},");
            sb.Append($"PasswordHash={SqlizeNoSanitize(user.PasswordHash)},");
            sb.Append($"PhoneNumber={SqlizeNoSanitize(user.PhoneNumber)},");
            sb.Append($"PhoneNumberConfirmed={Sqlize(user.PhoneNumberConfirmed)},");
            sb.Append($"TwoFactorEnabled={Sqlize(user.TwoFactorEnabled)},");
            sb.Append($"SecurityStamp={SqlizeNoSanitize(user.SecurityStamp)},");
            sb.Append($"Enabled={Sqlize(user.Enabled)},");
            sb.Append($"LockoutEnabled={Sqlize(user.LockoutEnabled)},");
            sb.Append($"LockoutEnd={Sqlize(user.LockoutEnd)}");

            sb.Append($" WHERE Id={SqlizeNoSanitize(user.UserId)};");

            return ExecNonQuery(sb.ToString(), prefix);
        }


        public bool UpdateWithConcurrencyStamp(ApplicationUser user)
        {
            string prefix = nameof(UpdateWithConcurrencyStamp) + Constants.FNSUFFIX;

            if (!IsSqlSanitizeValid(user.Email, MAXSIZE_EMAIL))
                throw new ArgumentException($"Email address [{user.Email}] does not pass SQL Sanitization; Check for typo errors, or choose alternative email address.");

            StringBuilder sb = new StringBuilder();

            sb.Append("EXEC UpdateUserWithConcurrencyStamp ");
            sb.Append($"{SqlizeNoSanitize(user.UserId)} ");
            sb.Append($"{GetDate()} ");
            sb.Append($"{user.AccessFailedCount} ");
            sb.Append($"{SqlizeNoSanitize(user.ConcurrencyStamp)} ");
            sb.Append($"{Sqlize(user.Email)} ");
            sb.Append($"{Sqlize(user.EmailNormalized)} ");
            sb.Append($"{Sqlize(user.EmailConfirmed)} ");
            sb.Append($"{Sqlize(user.LockoutEnabled)} ");
            sb.Append($"{Sqlize(user.LockoutEnd)} ");
            sb.Append($"{SqlizeNoSanitize(user.PasswordHash)} ");
            sb.Append($"{SqlizeNoSanitize(user.PhoneNumber)} ");
            sb.Append($"{Sqlize(user.PhoneNumberConfirmed)} ");
            sb.Append($"{SqlizeNoSanitize(user.SecurityStamp)} ");
            sb.Append($"{Sqlize(user.TwoFactorEnabled)} ");
            sb.Append($"{Sqlize(user.Enabled)}");

            sb.Append(";");

            return ExecNonQuery(sb.ToString(), prefix);
        }
    }
}
