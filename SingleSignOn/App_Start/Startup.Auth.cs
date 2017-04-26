using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using SingleSignOn.Models;
using System.Threading.Tasks;
using System.Security.Claims;

namespace SingleSignOn
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "e5cddf39-d5bc-4d7c-b6d7-8ba6f886d712",
            //    clientSecret: "9fn4XBbXM48OoT33ByNxKoX");

                var msaccountOptions = new Microsoft.Owin.Security.MicrosoftAccount.MicrosoftAccountAuthenticationOptions()
                {
                    ClientId = "e5cddf39-d5bc-4d7c-b6d7-8ba6f886d712",
                    ClientSecret = "9fn4XBbXM48OoT33ByNxKoX",
                    // See https://azure.microsoft.com/documentation/articles/active-directory-v2-scopes/
                    Provider = new Microsoft.Owin.Security.MicrosoftAccount.MicrosoftAccountAuthenticationProvider()
                    {
                        OnAuthenticated = (context) =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:microsoftaccount:access_token", context.AccessToken, "Microsoft"));


                            if (context.Email != null) context.Identity.AddClaim(new Claim("urn:microsoft:email", context.Email));
                            if (context.Id != null) context.Identity.AddClaim(new Claim("urn:microsoft:id", context.Id));
                            if (context.Name != null) context.Identity.AddClaim(new Claim("urn:microsoft:name", context.Name));
                            if (context.FirstName != null) context.Identity.AddClaim(new Claim("urn:microsoft:first_name", context.FirstName));
                            if (context.LastName != null) context.Identity.AddClaim(new Claim("urn:microsoft:last_name", context.LastName));

                            // Add all other available claims
                            foreach (var claim in context.User)
                            {
                                var claimType = string.Format("urn:microsoft:{0}", claim.Key);
                                var claimValue = claim.Value.ToString();
                                if (!context.Identity.HasClaim(claimType, claimValue))
                                    context.Identity.AddClaim(new Claim(claimType, claimValue, "XmlSchemaString", "Microsoft"));
                            }
                            return Task.FromResult(0);
                        }
                    }
                };

                app.UseMicrosoftAccountAuthentication(msaccountOptions);
            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "",
            //   appSecret: "");

            var googleOptions = new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "89411883579-k0prpkjbums65solhhiam5413t19htgu.apps.googleusercontent.com",
                ClientSecret = "yUPDN6onwUnkGm4jq_WGwkoQ",
                CallbackPath = new PathString("/signin-google"),
                Provider = new GoogleOAuth2AuthenticationProvider()
                {
                    OnAuthenticated = (context) =>
                    {
                        context.Identity.AddClaim(new Claim("urn:google:name", context.Identity.FindFirstValue(ClaimTypes.Name)));
                        context.Identity.AddClaim(new Claim("urn:google:email", context.Identity.FindFirstValue(ClaimTypes.Email)));
                        //This following line is need to retrieve the profile image
                        context.Identity.AddClaim(new System.Security.Claims.Claim("urn:google:accesstoken", context.AccessToken, ClaimValueTypes.String, "Google"));

                        return Task.FromResult(0);
                    }
                }
            };

            app.UseGoogleAuthentication(googleOptions);
        }
    }
}