using System.ComponentModel.DataAnnotations;

namespace Identity.WebApi.Module
{
    public class FriendLists
    {
        [Required]
        public string Id { get; set; }

        public required List<string> FriendList { get; set; }

    }
}
