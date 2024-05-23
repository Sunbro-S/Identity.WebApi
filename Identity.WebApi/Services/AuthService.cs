using Azure.Core;
using Identity.WebApi.Context;
using Identity.WebApi.Module;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Identity.WebApi.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ExtendedIdentityUser> _userManager;
        private readonly IConfiguration _config;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly AuthDbContext _context;
        public AuthService(UserManager<ExtendedIdentityUser> userManager, IConfiguration config, RoleManager<IdentityRole> roleManager, AuthDbContext context)
        {
            _userManager = userManager;
            _config = config;
            _roleManager = roleManager;
            _context = context;
        }

        public async Task<bool> AddUserWithRoles(RegisterUser userInfo)
        {
            var user = new ExtendedIdentityUser { UserName = userInfo.UserName, Email = userInfo.Email };
            var result = await _userManager.CreateAsync(user, userInfo.Password);
            if (!result.Succeeded)
                throw new InvalidOperationException($"Tried to add user {user.UserName}, but failed.");

            foreach (var roleName in userInfo.RolesCommaDelimited.Split(',').Select(x => x.Trim()))
            {
                var roleExist = await _roleManager.RoleExistsAsync(roleName);
                if (!roleExist)
                {
                    await _roleManager.CreateAsync(new IdentityRole(roleName));
                }
                await _userManager.AddToRoleAsync(user, roleName);
            }
            var fullname = userInfo.FullName.Split(" ");
            var userinfo = new Users
            {
                UserId = user.Id,
                UserName = user.UserName,
                Mail = user.Email,
                Name = fullname[1],
                Lastname = fullname[0],
                Otchestvo = fullname[2]
            };

            var newFriendList = new FriendLists
            {
                Id = user.Id,
                FriendList = new List< string> { }
            };

            _context.FriendLists.Add(newFriendList);
            _context.Users.Add(userinfo);
            await _context.SaveChangesAsync();
            return result.Succeeded;
        }

        public async Task<LoginResponse> Login(LoginUser user)
        {
            ExtendedIdentityUser? identityUser = null;

            var response = new LoginResponse();
            if ( user.Login!= null)
            {
                identityUser = await _userManager.FindByNameAsync(user.Login);
                if (identityUser == null)
                    identityUser = await _userManager.FindByEmailAsync(user.Login);
            }

            if (identityUser is null || (await _userManager.CheckPasswordAsync(identityUser, user.Password)) == false)
            {
                return response;
            }

            response.IsLogedIn = true;
            response.JwtToken = this.GenerateTokenString(identityUser);
            response.RefreshToken = this.GenerateRefreshTokenString();

            identityUser.RefreshToken = response.RefreshToken;
            identityUser.RefreshTokenExpiry = DateTime.UtcNow.AddHours(12);
            await _userManager.UpdateAsync(identityUser);

            return response;
        }

        public async Task<LoginResponse> Logout(HttpRequest request)
        {
            string authHeader = request.Headers["Authorization"].FirstOrDefault();
            if (authHeader == null || !authHeader.StartsWith("Bearer "))
            {
                throw new InvalidOperationException("Invalid token.");
            }

            string accessToken = authHeader.Substring("Bearer ".Length).Trim();
            var response = new LoginResponse();
            var userEmail = GetClaimFromAccessToken(accessToken, ClaimTypes.Email);
            var user = await _userManager.FindByEmailAsync(userEmail);


            user.RefreshToken = null;
            user.RefreshTokenExpiry = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);


            response.IsLogedIn = false;
            response.JwtToken = null;
            response.RefreshToken = null;

            return response;
        }

        private string GetClaimFromAccessToken(string accessToken, string claimType)
        {
            var claims = DecodeAccessToken(accessToken);
            var claim = claims.FirstOrDefault(c => c.Type == claimType);
            return claim?.Value;
        }

        private List<Claim> DecodeAccessToken(string accessToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _config.GetSection("Jwt:Issuer").Value,
                ValidAudience = _config.GetSection("Jwt:Audience").Value,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };

            try
            {
                var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken validatedToken);
                return principal.Claims.ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при расшифровке токена: {ex.Message}");
                return null;
            }
        }

        public async Task<LoginResponse> RefreshToken(RefreshTokenModel model)
        {
            var principal = GetTokenPrincipal(model.JwtToken);

            var response = new LoginResponse();
            if (principal?.Identity?.Name is null)
                return response;

            var identityUser = await _userManager.FindByNameAsync(principal.Identity.Name);

            if (identityUser is null || identityUser.RefreshToken != model.RefreshToken || identityUser.RefreshTokenExpiry < DateTime.UtcNow)
                return response;

            response.IsLogedIn = true;
            response.JwtToken = this.GenerateTokenString(identityUser);
            response.RefreshToken = this.GenerateRefreshTokenString();

            identityUser.RefreshToken = response.RefreshToken;
            identityUser.RefreshTokenExpiry = DateTime.UtcNow.AddHours(12);
            await _userManager.UpdateAsync(identityUser);

            return response;
        }

        public async Task<UsersSerchResult> GetUserByLogin(string friendName)
        {
            var user = await _userManager.FindByNameAsync(friendName);

            if (user == null)
            {
               throw new InvalidOperationException ("User not found");
            }

            var userInfo = await _context.Users.FindAsync(user.Id);
            var result = new UsersSerchResult() 
            {
                Username = user.UserName,
                Fullname = $"{userInfo.Lastname} {userInfo.Name} {userInfo.Otchestvo}"
            };
            return result;
        }
       
        public async Task<List<string>> GetFriendList(HttpRequest request)
        {
            string authHeader = request.Headers["Authorization"].FirstOrDefault();
            if (authHeader == null || !authHeader.StartsWith("Bearer "))
            {
                throw new InvalidOperationException("Invalid token.");
            }

            string accessToken = authHeader.Substring("Bearer ".Length).Trim();
            var response = new LoginResponse();
            var userEmail = GetClaimFromAccessToken(accessToken, ClaimTypes.Email);
            var user = await _userManager.FindByEmailAsync(userEmail);
            var friendList = await _context.FriendLists.FindAsync(user.Id);
            return friendList.FriendList;

        }

        public async Task<LoginResponse> DeleteAccount(HttpRequest request)
        {
            string authHeader = request.Headers["Authorization"].FirstOrDefault();
            if (authHeader == null || !authHeader.StartsWith("Bearer "))
            {
                throw new InvalidOperationException("Invalid token.");
            }

            string accessToken = authHeader.Substring("Bearer ".Length).Trim();
            var userEmail = GetClaimFromAccessToken(accessToken, ClaimTypes.Email);
            var user = await _userManager.FindByEmailAsync(userEmail);
            var response = new LoginResponse();
            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException("Error deleting user.");
            }

            var userInfo = await _context.Users.FindAsync(user.Id);
            if (userInfo != null)
            {
                _context.Users.Remove(userInfo);
            }

            var friendList = await _context.FriendLists.FindAsync(user.Id);
            if (friendList != null)
            {
                _context.FriendLists.Remove(friendList);
            }

            await _context.SaveChangesAsync();

            response.IsLogedIn = false;
            response.JwtToken = null;
            response.RefreshToken = null;
            return response;
        }

        public async Task<LoginResponse> PutAccountChanges(HttpRequest request, UpdateUserModel updateUserModel)
        {
            string authHeader = request.Headers["Authorization"].FirstOrDefault();
            if (authHeader == null || !authHeader.StartsWith("Bearer "))
            {
                throw new InvalidOperationException("Invalid token.");
            }

            string accessToken = authHeader.Substring("Bearer ".Length).Trim();

            var userEmail = GetClaimFromAccessToken(accessToken, ClaimTypes.Email);

            var user = await _userManager.FindByEmailAsync(userEmail);
            var userInfo = await _context.Users.FindAsync(user.Id);
            if (user == null)
            {
                throw new InvalidOperationException("User not found.");
            }

            if (!string.IsNullOrEmpty(updateUserModel.UserName))
            {
                user.UserName = updateUserModel.UserName;
            }
            if (!string.IsNullOrEmpty(updateUserModel.Email))
            {
                user.Email = updateUserModel.Email;
            }
            if (!string.IsNullOrEmpty(updateUserModel.Password))
            {
                user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, updateUserModel.Password);
            }
            if (!string.IsNullOrEmpty(updateUserModel.FullName))
            {
                var fullName = updateUserModel.FullName;
                userInfo.Name = fullName.Split(" ")[1];
                userInfo.Lastname = fullName.Split(" ")[0];
                userInfo.Otchestvo = fullName.Split(" ")[3];
            }
            var response = new LoginResponse();
            response.IsLogedIn = true;
            response.JwtToken = this.GenerateTokenString(user);
            response.RefreshToken = this.GenerateRefreshTokenString();

            user.RefreshToken = response.RefreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddHours(12);
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException("Error updating user.");
            }
            if (userInfo != null)
            {
                userInfo.UserName = user.UserName;
                userInfo.Mail = user.Email;

                _context.Users.Update(userInfo);
                await _context.SaveChangesAsync();
            }

            return response;
        }

        private ClaimsPrincipal? GetTokenPrincipal(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value));
            var validation = new TokenValidationParameters
            {
                IssuerSigningKey = securityKey,
                ValidateLifetime = false,
                ValidateActor = false,
                ValidateIssuer = false,
                ValidateAudience = false,
            };

            return new JwtSecurityTokenHandler().ValidateToken(token, validation, out _);

        }

        private string GenerateRefreshTokenString()
        {
            var randomNumber = new byte[64];

            using (var numberGenerator = RandomNumberGenerator.Create())
            {
                numberGenerator.GetBytes(randomNumber);
            }

            return Convert.ToBase64String(randomNumber);
        }


        public string GenerateTokenString(ExtendedIdentityUser user)
        {
            var role = _userManager.GetRolesAsync(user).Result.First();
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, role),
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value));

            var signingCred = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var securityToken = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(60),
                issuer: _config.GetSection("Jwt:Issuer").Value,
                audience: _config.GetSection("Jwt:Audience").Value,
                signingCredentials: signingCred);

            string tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);
            return tokenString;
        }
    }
}
