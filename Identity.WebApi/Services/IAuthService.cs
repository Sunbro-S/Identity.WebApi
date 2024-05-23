
using Identity.WebApi.Module;

namespace Identity.WebApi.Services
{
    public interface IAuthService
    {
        Task<LoginResponse> Login(LoginUser user);
        Task<LoginResponse> RefreshToken(RefreshTokenModel model);
        Task<bool> AddUserWithRoles(RegisterUser userInfo);
        Task<LoginResponse> Logout(HttpRequest request);
        Task<UsersSerchResult> GetUserByLogin(string friendName);
        Task<List<string>> GetFriendList(HttpRequest request);
        Task<LoginResponse> DeleteAccount(HttpRequest request);
        Task<LoginResponse> PutAccountChanges(HttpRequest request, UpdateUserModel updateUserModel);
    }
}