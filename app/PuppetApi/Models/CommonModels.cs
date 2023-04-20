using Newtonsoft.Json.Linq;
using System.Text.Json.Serialization;

namespace PuppetApi.Models
{
    public class HieraApiQueryData
    {
        // Environment (Node group) name is used to populate Hiera search with correct Puppet Console variables:
        //   Example:  puppet lookup --environment 2022_4 --merge deep --render-as json --facts ~/facts.json profile::admin_app_iis_api::appsettings
        [JsonPropertyName("environment")]
        public string? Environment { get; set; }     // P1S environment name, based on naming of Puppet Node groups
        [JsonPropertyName("branch")]
        public string? Branch { get; set; }          // Puppet environment, or git branch name
        [JsonPropertyName("hierasearchkey")]
        public string? HieraSearchKey { get; set; }  // Hiera key that you are searching for value
    }
    public class HieraData
    {
        public JToken? ConsoleVariables { get; set; }
        public string? HieraSearchValue { get; set; }
    }
}
