using JWTASP.NETCoreWebAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static JWTASP.NETCoreWebAPI.Models.AppDbContext;
using static JWTASP.NETCoreWebAPI.Models.Models;

namespace JWTASP.NETCoreWebAPI.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpPost("login")]
        [AllowAnonymous]
        public IActionResult Login(LoginModel user)
        {
            AppDbContext _db = new AppDbContext();
            User u = new User();
            u.Email = user.Email;
            u.Password = user.Password;
            var normalUser = _db.AuthenticateNormalUser(u);
            var adminUser = _db.AuthenticateAdminUser(u);

            if (!(normalUser || adminUser))
                return Unauthorized();

            var issuer = _configuration["Jwt:Issuer"];
            var audience = _configuration["Jwt:Audience"];
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"] ?? string.Empty);
            var claims = new[]
                            {
                            new Claim("Id", Guid.NewGuid().ToString()),
                            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                            new Claim(JwtRegisteredClaimNames.Email, user.Email),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                        };

            if (adminUser)
            {
                claims = claims.Append(new Claim(ClaimTypes.Role, "admin")).ToArray();
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(5), // should be at least 5 minutes
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var stringToken = tokenHandler.WriteToken(token);

            return Ok(new TokenResponseModel(stringToken));
        }

    }
}
