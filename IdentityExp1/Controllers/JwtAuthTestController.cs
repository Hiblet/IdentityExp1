using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace IdentityExp1.Controllers
{
    [Route("api/test")]
    public class JwtAuthTestController : Controller
    {
        private readonly JsonSerializerSettings _serializerSettings;

        public JwtAuthTestController()
        {
            _serializerSettings = new JsonSerializerSettings { Formatting = Formatting.Indented };
        }

        // This is just an action protected by an example policy
        [HttpGet]
        //[Authorize(Policy = "CheckWorking")]
        public IActionResult Get()
        {
            var response = new { made_it = "Hello!" };

            var json = JsonConvert.SerializeObject(response, _serializerSettings);
            return new OkObjectResult(json);
        }
    }
}