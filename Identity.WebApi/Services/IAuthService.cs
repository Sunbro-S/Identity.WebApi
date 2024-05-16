
using Identity.WebApi.Module;

namespace Identity.WebApi.Services
{
    public interface IAuthService
    {
        string GenerateTokenString(LoginUser user);
        Task<bool> Login(LoginUser user);
        Task<bool> AddUserWithRoles(LoginUser userInfo);
    }
}