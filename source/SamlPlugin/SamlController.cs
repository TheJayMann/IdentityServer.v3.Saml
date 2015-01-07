/*
 * Copyright 2014 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.IdentityModel.Services;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Thinktecture.IdentityServer.Core;
using Thinktecture.IdentityServer.Core.Configuration;
using Thinktecture.IdentityServer.Core.Extensions;
using Thinktecture.IdentityServer.Core.Logging;
using Thinktecture.IdentityServer.Core.Models;
using Thinktecture.IdentityServer.Core.Results;
using Thinktecture.IdentityServer.Core.Services;
using IdentityServer.v3.Saml.Configuration;
using IdentityServer.v3.Saml.Hosting;
using IdentityServer.v3.Saml.ResponseHandling;
using IdentityServer.v3.Saml.Results;
using IdentityServer.v3.Saml.Services;
using IdentityServer.v3.Saml.Validation;

namespace IdentityServer.v3.Saml
{
    [HostAuthentication(Constants.PrimaryAuthenticationType)]
    [RoutePrefix("")]
    [NoCache]
    [SecurityHeaders(EnableCsp=false)]
    public class SamlController : ApiController
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        private readonly IdentityServerOptions _options;
        private readonly SignInValidator _validator;
        private readonly SignInResponseGenerator _signInResponseGenerator;
        private readonly MetadataResponseGenerator _metadataResponseGenerator;
        private readonly ITrackingCookieService _cookies;
        private readonly SamlPluginOptions _samlOptions;

        public SamlController(IdentityServerOptions options, IUserService users, SignInValidator validator, SignInResponseGenerator signInResponseGenerator, MetadataResponseGenerator metadataResponseGenerator, ITrackingCookieService cookies, SamlPluginOptions pluginOptions)
        {
            _options = options;
            _validator = validator;
            _signInResponseGenerator = signInResponseGenerator;
            _metadataResponseGenerator = metadataResponseGenerator;
            _cookies = cookies;
            _samlOptions = pluginOptions;
        }

        [Route("")]
        public async Task<IHttpActionResult> Get()
        {
            Logger.Info("Start Saml request");
            Logger.Debug(Request.RequestUri.AbsoluteUri);

            WSFederationMessage message;
            if (WSFederationMessage.TryCreateFromUri(Request.RequestUri, out message))
            {
                var signin = message as SignInRequestMessage;
                if (signin != null)
                {
                    Logger.Info("Saml signin request");
                    return await ProcessSignInAsync(signin);
                }

                var signout = message as SignOutRequestMessage;
                if (signout != null)
                {
                    Logger.Info("Saml signout request");

                    var url = this.Request.GetOwinContext().Environment.GetIdentityServerLogoutUrl();
                    return Redirect(url);
                }
            }

            return BadRequest("Invalid Saml request");
        }

        [Route("signout")]
        [HttpGet]
        public async Task<IHttpActionResult> SignOutCallback()
        {
            Logger.Info("Saml signout callback");

            var urls = await _cookies.GetValuesAndDeleteCookieAsync(SamlPluginOptions.CookieName);
            return new SignOutResult(urls);
        }

        [Route("metadata")]
        public IHttpActionResult GetMetadata()
        {
            Logger.Info("Saml metadata request");

            if (_samlOptions.MetadataEndpoint.IsEnabled == false)
            {
                Logger.Warn("Endpoint is disabled. Aborting.");
                return NotFound();
            }

            var sign = bool.Parse((Request.GetOwinContext().Request.Query.Get("sign") ?? "true"));

            return new MetadataResult(sign, _options.SigningCertificate);
        }

        private async Task<IHttpActionResult> ProcessSignInAsync(SignInRequestMessage msg)
        {
            var result = await _validator.ValidateAsync(msg, User as ClaimsPrincipal);

            if (result.IsSignInRequired)
            {
                return RedirectToLogin(result);
            }
            if (result.IsError)
            {
                return BadRequest(result.Error);
            }

            var responseMessage = await _signInResponseGenerator.GenerateResponseAsync(result);
            await _cookies.AddValueAsync(SamlPluginOptions.CookieName, result.ReplyUrl);

            return new SignInResult(responseMessage);
        }

        IHttpActionResult RedirectToLogin(SignInValidationResult result)
        {
            var message = new SignInMessage();
            message.ReturnUrl = Request.RequestUri.AbsoluteUri;

            if (result.HomeRealm.IsPresent())
            {
                message.IdP = result.HomeRealm;
            }

            var url = LoginResult.GetRedirectUrl(message, this.Request.GetOwinContext().Environment, _options);
            return Redirect(url);
        }
    }
}