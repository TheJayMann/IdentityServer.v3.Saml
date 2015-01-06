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

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System;
using IdentityServer.v3.Saml.Configuration;
using IdentityServer.v3.Saml.Hosting;

namespace Thinktecture.IdentityServer.Core.Configuration
{
    public static class PluginAppBuilderExtensions
    {
        public static IAppBuilder UseSamlPlugin(this IAppBuilder app, SamlPluginOptions options)
        {
            if (options == null) throw new ArgumentNullException("options");
            options.Validate();

            options.IdentityServerOptions.ProtocolLogoutUrls.Add(options.LogoutUrl);

            app.Map(options.MapPath, wsfedApp =>
                {
                    wsfedApp.UseCookieAuthentication(new CookieAuthenticationOptions
                    {
                        AuthenticationType = SamlPluginOptions.CookieName,
                        AuthenticationMode = AuthenticationMode.Passive,
                        CookieName = options.IdentityServerOptions.AuthenticationOptions.CookieOptions.Prefix + SamlPluginOptions.CookieName,
                    });

                    wsfedApp.Use<AutofacContainerMiddleware>(AutofacConfig.Configure(options));
                    Microsoft.Owin.Infrastructure.SignatureConversions.AddConversions(app);
                    wsfedApp.UseWebApi(WebApiConfig.Configure());
                });

            return app;
        }
    }
}