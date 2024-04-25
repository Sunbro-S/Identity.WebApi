
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace Identity.WebApi.Module
{
    [Keyless]
    public class Users
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string Mail { get; set; }
        public string OpenedRooms { get; set; }
        public string CreatedRooms { get; set; }
        public string Icon { get;set; }
    }
}
