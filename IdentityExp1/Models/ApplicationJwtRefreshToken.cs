namespace NZ01
{
    public class ApplicationJwtRefreshToken
    {
        public string Guid { get; set; }
        public string Name { get; set; } // Name of User that this token belongs to
        public string IP { get; set; } // IP address that the token applies to
    }
}
