using JwtAuthProject.Entities;
using JwtAuthProject.Models;

namespace JwtAuthProject.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDTO request);
        Task<TokenResponseDTO?> LoginAsync(UserDTO request);
        Task<TokenResponseDTO?> RequestRefreshToken(RequestRefreshTokenDTO request);
    }
}
