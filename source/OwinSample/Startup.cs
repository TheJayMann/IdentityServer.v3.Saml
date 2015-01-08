using OwinSample.Config;
using Owin;
using System.Linq;
using System.Collections.Generic;
using Thinktecture.IdentityServer.Core.Configuration;
using Thinktecture.IdentityServer.Core.Services.InMemory;
using IdentityServer.OwinSample.Config;
using IdentityServer.v3.Saml.Configuration;
using IdentityServer.v3.Saml.Models;
using IdentityServer.v3.Saml.Services;
using Microsoft.Owin.Security.OpenIdConnect;

namespace OwinSample
{
    internal class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // /core represents the server portion of the OpenIdConnect
            // this is IdentityServer itself
            app.Map("/core", coreApp => {
                coreApp.Use(async (ctx, next) => {
                    await next();
                });

                var factory = InMemoryFactory.Create(
                    users: Users.Get(),
                    clients: Clients.Get(),
                    scopes: Scopes.Get());

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

            // /client represents the client application. This will talk to /core (the server) 
            // to negotiate authentication using OpenIdConnect. As the client, you need the following nuget packages:
            // 
            app.Map("/client", clientApp => {
                clientApp.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
                {
                    ClientId = "client",
                    Authority = "https://localhost:44334/core",

                    RedirectUri = "https://localhost:44334/",
                    PostLogoutRedirectUri = "https://localhost:44334/",

                    SignInAsAuthenticationType = "client"
                });
                clientApp.Run(c => {
                    if (c.Authentication.User != null &&
                        c.Authentication.User.Identity != null &&
                        c.Authentication.User.Identity.IsAuthenticated) {
                        return c.Response.WriteAsync("hello world - authenticated");
                    } else {
                        c.Authentication.Challenge(c.Authentication.GetAuthenticationTypes().Select(d => d.AuthenticationType).ToArray());
                        return System.Threading.Tasks.Task.Delay(0);
                    }
                });
            });
        }

        private void ConfigurePlugins(IAppBuilder pluginApp, IdentityServerOptions options)
        {
            var factory = new SamlServiceFactory
            {
                UserService = options.Factory.UserService,
                ServiceProviderService = new Registration<IServiceProviderService>(typeof(InMemoryServiceProviderService))
            };

            // data sources for in-memory services
            factory.Register(new Registration<IEnumerable<ServiceProvider>>(ServiceProviders.Get()));

            var samlOptions = new SamlPluginOptions
            {
                IdentityServerOptions = options,
                Factory = factory
            };

            pluginApp.UseSamlPlugin(samlOptions);
        }
    }
}