using Host.Config;
using Owin;
using System.Collections.Generic;
using Thinktecture.IdentityServer.Core.Configuration;
using Thinktecture.IdentityServer.Core.Services.InMemory;
using Thinktecture.IdentityServer.Host.Config;
using IdentityServer.v3.Saml.Configuration;
using IdentityServer.v3.Saml.Models;
using IdentityServer.v3.Saml.Services;

namespace Host
{
    internal class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.Map("/core", coreApp =>
            {
                coreApp.Use(async (ctx, next) =>
                {
                    await next();
                });
                
                var factory = InMemoryFactory.Create(
                    users:   Users.Get(),
                    clients: Clients.Get(),
                    scopes:  Scopes.Get());

                var options = new IdentityServerOptions
                {
                    IssuerUri = "https://idsrv3.com",
                    SiteName = "Thinktecture IdentityServer v3",

                    SigningCertificate = Certificate.Get(),
                    Factory = factory,
                    PluginConfiguration = ConfigurePlugins,
                };

                coreApp.UseIdentityServer(options);
            });
        }

        private void ConfigurePlugins(IAppBuilder pluginApp, IdentityServerOptions options)
        {
            var factory = new WsFederationServiceFactory
            {
                UserService = options.Factory.UserService,
                RelyingPartyService = new Registration<IServiceProviderService>(typeof(InMemoryServiceProviderService))
            };

            // data sources for in-memory services
            factory.Register(new Registration<IEnumerable<ServiceProvider>>(RelyingParties.Get()));

            var wsFedOptions = new WsFederationPluginOptions
            {
                IdentityServerOptions = options,
                Factory = factory
            };

            pluginApp.UseWsFederationPlugin(wsFedOptions);
        }
    }
}