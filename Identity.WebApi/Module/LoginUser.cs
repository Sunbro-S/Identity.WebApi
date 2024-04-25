namespace Identity.WebApi.Module
{
    public class LoginUser
    {
        public string UserName { get; set; }
        public string Password { get; set; }

        /// <summary>
        /// List of RoleNames, comma delimited
        /// </summary>
        public string RolesCommaDelimited { get; set; }

    }
}
