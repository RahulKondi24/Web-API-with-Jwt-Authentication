namespace JWTASP.NETCoreWebAPI.Models
{
    public class Models
    {
        public record RegisterModel(string Email, string Password);
        public record LoginModel(string Email, string Password);
        public record TokenResponseModel(string Token);

    }
    public class AppDbContext
    {
        public static List<User> dummyUsers = new List<User>
                                        {
                                            new User {Email="user1@example.com",Password = "user@123" ,Role="User"},
                                            new User {Email="Admin@example.com",Password = "Admin@456" ,Role="Admin"},
                                            new User {Email="user2@example.com",Password = "user@789" ,Role="User"},
                                        };
        public List<User> Users()
        {
            return dummyUsers;
        }
        public List<UserResponseDTO> GetUsersWithoutPasswords()
        {
            
            var usersWithoutPasswords = dummyUsers.Select(user => new UserResponseDTO
            {
                Email = user.Email,
                Role = user.Role
            }).ToList();

            return usersWithoutPasswords;
        }
        public bool AuthenticateNormalUser(User user)
        {
            if (user != null)
            {
                var data = dummyUsers.Where(e => e.Email == user.Email).FirstOrDefault();
                if (data != null)
                {
                    if (data.Role == "User")
                    {
                        return true;
                    }
                    return false;
                }
            }
            return false;
        }
        public bool AuthenticateAdminUser(User user)
        {
            if (user != null)
            {
                var data = dummyUsers.Where(e => e.Email == user.Email).FirstOrDefault();
                if (data != null)
                {
                    if (data.Role == "Admin")
                    {
                        return true;
                    }
                    return false;
                }
            }
            return false;
        }
    }
    public class User
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }
    public class UserResponseDTO
    {
        public string Email { get; set; }
        public string Role { get; set; }
    }
}
