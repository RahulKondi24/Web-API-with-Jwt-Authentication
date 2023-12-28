using JWTASP.NETCoreWebAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTASP.NETCoreWebAPI.Controllers
{
    [Route("api/user")]
    [ApiController]
    public class UserController : ControllerBase
    {
        AppDbContext _db = new AppDbContext();

        [HttpGet("get-users")]
        [Authorize]
        public IEnumerable<UserResponseDTO> GetUsersWithoutPasswords()
        {
            var data = _db.GetUsersWithoutPasswords();
            return data;
        }

        [HttpGet("get-admin-users")]
        [Authorize(Roles = "admin")]
        public IEnumerable<User> GetAllUsersWithPassword()
        {
            var data = _db.Users();
            return data;
        }
    }
}
