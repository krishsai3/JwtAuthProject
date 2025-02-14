using JwtAuthProject.Data;
using JwtAuthProject.Entities;
using JwtAuthProject.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthProject.Services
{
    public class AuthService(UserDbContext dbContext, IConfiguration configuration ) : IAuthService
    {
        public async Task<TokenResponseDTO?> LoginAsync(UserDTO request)
        {
            var user = await dbContext.Users.FirstOrDefaultAsync(x => x.Username == request.Username);
            if (user is null)
            {
                return null;
            }
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return null;
            }

            TokenResponseDTO tokenResponse = await GenerateAccessRefreshTokens(user);

            return tokenResponse;
        }

        private async Task<TokenResponseDTO> GenerateAccessRefreshTokens(User user)
        {
            return new TokenResponseDTO
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateAndSaveRefreshToken(user)
            };
        }

        public async Task<TokenResponseDTO?> RequestRefreshToken(RequestRefreshTokenDTO request)
        {
            var storedResponse = await dbContext.Users.FindAsync(request.UserId);
            if(storedResponse is null || storedResponse.RefreshToken != request.RefreshToken 
                || storedResponse.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return null;
            }
            

            return await GenerateAccessRefreshTokens(storedResponse);
        }

        public async Task<User?> RegisterAsync(UserDTO request)
        {
            if(await dbContext.Users.AnyAsync(x=>x.Username == request.Username))
            {
                return null;
            }

            var user = new User();
            var hashedPassword = new PasswordHasher<User>().HashPassword(user,request.Password);

            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            dbContext.Users.Add(user);
            await dbContext.SaveChangesAsync();

            return user;
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public async Task<string> GenerateAndSaveRefreshToken(User user)
        {
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await dbContext.SaveChangesAsync();
            return refreshToken;
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,user.Username),
                new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                new Claim(ClaimTypes.Role,user.Role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}
