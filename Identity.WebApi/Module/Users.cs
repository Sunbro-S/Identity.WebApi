
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace Identity.WebApi.Module
{
    [Keyless]
    public class Users
    {
        public int UserId { get; set; }

        public int year { get; set; }

        public string UserName { get; set; }
        public string Mail { get; set; }
    }
}
