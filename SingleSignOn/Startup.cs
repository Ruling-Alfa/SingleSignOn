using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(SingleSignOn.Startup))]
namespace SingleSignOn
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
