﻿
using Identity.WebApi.Module;

namespace Identity.WebApi.Services
{
    public interface IAuthService
    {
        Task<LoginResponse> Login(LoginUser user);
        Task<LoginResponse> RefreshToken(RefreshTokenModel model);
        Task<bool> AddUserWithRoles(RegisterUser userInfo);
        Task<LoginResponse> Logout(HttpRequest request);
    }
}