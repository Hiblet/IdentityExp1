namespace NZ01
{
    public class ApplicationRole
    {
        public string RoleId { get; set; }
        public string RoleName { get; set; }
        public string RoleNameNormalized => RoleName?.ToUpper();
        public string ConcurrencyStamp { get; set; }
    }

    public class ExampleApplicationRole
    {
        public string RoleId { get; set; }
        public string RoleName { get; set; }
        public string RoleNameNormalized => RoleName?.ToUpper();
    }
}

/*
namespace IdentityExp1.Models
{
    public class ApplicationRole
    {
        public string RoleId { get; set; }
        public string RoleName { get; set; }
        public string RoleNameNormalized => RoleName?.ToUpper();
    }
}
*/