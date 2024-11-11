namespace JwtAuthApi.Models
{
    public class User
    {
        public int Id { get; set; }
        public required string FullName { get; set; }
        public DateTime BirthDate { get; set; }
        public required string Email { get; set; }
        public required string PasswordHash { get; set; }
    }
}
