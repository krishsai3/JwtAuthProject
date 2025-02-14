using JwtAuthProject.Entities;
using JwtAuthProject.Models;
using JwtAuthProject.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        public static User user = new();

        [HttpPost("register")]
        public async Task<ActionResult<User>> RegisterUser(UserDTO request)
        {
            var user = await authService.RegisterAsync(request);

            if (user is null)
            {
                return BadRequest("Username already exists");
            }

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDTO>> Login(UserDTO request)
        {
            var result = await authService.LoginAsync(request);

            if (result is null)
            {
                return BadRequest("Invalid user name or password");
            }

            return Ok(result);
        }

        [HttpPost("generate-refresh-token")]
        public async Task<ActionResult<TokenResponseDTO>> RequestRefreshToken(RequestRefreshTokenDTO request)
        {
            var result = await authService.RequestRefreshToken(request);
            if(result is null || result.AccessToken == null || result.RefreshToken == null)
            {
                return Unauthorized("Invalid Refresh Token");
            }

            return Ok(result);
        }

        [Authorize]
        [HttpGet("authenticate")]
        public IActionResult TestAuthenticateMethod()
        {
            return Ok("You are authenticated");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndpoint()
        {
            return Ok("Hi, Admin!");
        }
    }
}