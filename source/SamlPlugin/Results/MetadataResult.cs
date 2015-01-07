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

using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using Thinktecture.IdentityServer.Core.Logging;

namespace IdentityServer.v3.Saml.Results
{
    public class MetadataResult : IHttpActionResult
    {
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();
        private readonly X509Certificate2 _certificate;
        private readonly bool _sign;

        public MetadataResult(bool sign, System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        {
            _sign = sign;
            _certificate = certificate;
        }

        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Execute());
        }

        private HttpResponseMessage Execute()
        {
            var configuration = SAML2.Config.Saml2Config.GetConfig();
            configuration.ServiceProvider.SigningCertificate.Certificate = _certificate;

            var keyinfo = new System.Security.Cryptography.Xml.KeyInfo();
            var keyClause = new System.Security.Cryptography.Xml.KeyInfoX509Data(configuration.ServiceProvider.SigningCertificate.GetCertificate(),
                                    X509IncludeOption.EndCertOnly);
            keyinfo.AddClause(keyClause);

            var doc = new SAML2.Saml20MetadataDocument(configuration, keyinfo, _sign);

            var content = new StringContent(doc.ToXml(), Encoding.UTF8, "application/xml");

            Logger.Debug("Returning Saml metadata response");
            return new HttpResponseMessage { Content = content };
        }
    }
}