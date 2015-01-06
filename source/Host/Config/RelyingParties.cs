using System.Collections.Generic;
using System.Security.Claims;
using IdentityServer.v3.Saml.Models;

namespace Host.Config
{
    public class RelyingParties
    {
        public static IEnumerable<ServiceProvider> Get()
        {
            return new List<ServiceProvider>
            {   
                new ServiceProvider
                {
                    Realm = "urn:testrp",
                    Name = "Test RP",
                    Enabled = true,
                    ReplyUrl = "https://web.local/idsrvrp/",
                    TokenType = Thinktecture.IdentityModel.Constants.TokenTypes.Saml2TokenProfile11,
                    TokenLifeTime = 1,

                    ClaimMappings = new Dictionary<string,string>
                    {
                        { "sub", ClaimTypes.NameIdentifier },
                        { "given_name", ClaimTypes.Name },
                        { "email", ClaimTypes.Email }
                    }
                },
                new ServiceProvider
                {
                    Realm = "urn:owinrp",
                    Enabled = true,
                    ReplyUrl = "http://localhost:10313/",
                    TokenType = Thinktecture.IdentityModel.Constants.TokenTypes.JsonWebToken,
                    TokenLifeTime = 1,

                    ClaimMappings = new Dictionary<string, string>
                    {
                        { "sub", ClaimTypes.NameIdentifier },
                        { "name", ClaimTypes.Name },
                        { "given_name", ClaimTypes.GivenName },
                        { "email", ClaimTypes.Email }
                    }
                }
            };
        }
    }
}
