namespace JwtAuthProject.Models
{
    public class RequestRefreshTokenDTO
    {
        public Guid UserId { get; set; }
        public required string RefreshToken { get; set; }
    }
}
