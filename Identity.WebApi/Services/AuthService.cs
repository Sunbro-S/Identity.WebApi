using Identity.WebApi.Context;
using Identity.WebApi.Module;
using Microsoft.AspNetCore.Identity;
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

            var userinfo = new Users
            {
                UserId = user.Id,
                UserName = user.UserName,
                Mail = user.Email
            };
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
                // Валидация токена и извлечение утверждений
                var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken validatedToken);
                return principal.Claims.ToList();
            }
            catch (Exception ex)
            {
                // Логируйте или обрабатывайте ошибку, если необходимо
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

        private ClaimsPrincipal? GetTokenPrincipal(string token)
        {
            try
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
            catch (Exception ex)
            {
                // Логируйте ошибку или обработайте ее как требуется
                Console.WriteLine($"Ошибка при валидации токена: {ex.Message}");
                return null; // Или выбросите исключение, если это необходимо
            }
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
