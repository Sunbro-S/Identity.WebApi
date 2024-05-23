
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

namespace Identity.WebApi.Module
{
    public class Users
    {
        [Key]
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string Mail { get; set; }
        public string? Name { get; set; }
        public string? Lastname { get; set; }
        public string? Otchestvo { get; set; }
        public string? OpenedRooms { get; set; }
        public string? CreatedRooms { get; set; } = null;
        public string? Icon { get;set; } = null;
    }
}
