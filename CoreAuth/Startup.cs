using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using CoreAuth.Middleware;

namespace CoreAuth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();


            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        //ValidAudience = "the audience you want to validate",
                        ValidateIssuer = false,
                        //ValidIssuer = "the isser you want to validate",
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("the secret that needs to be at least 16 characeters long for HmacSha256")),
                        ValidateLifetime = true, //validate the expiration and not before values in the token                
                        ClockSkew = TimeSpan.FromMinutes(5) //5 minute tolerance for the expiration date
                    };
                });






            //services.AddAuthorization(options =>
            //{
            //    options.AddPolicy("Member", policy =>
            //    {
            //        policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
            //        policy.RequireRole("SuperAdmin");
            //        //policy.RequireClaim("name", "rconnolly@ashleyfurniture.com");
            //    });

            //    //options.AddPolicy("Member",
            //    //    policy => policy.RequireClaim("name", "rconnolly@ashleyfurniture.com"));

            //    //options.AddPolicy(
            //    //    "CanAccessVIPArea",
            //    //    //policyBuilder => policyBuilder.RequireClaim("VIPNumber")
            //    //    policyBuilder => policyBuilder.RequireRole("SuperAdmin")
            //    //);
            //});





            services.AddAuthorization(options =>
                options.AddPolicy("Member",
                policy =>
                {
                    policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
                    policy.Requirements.Add(new RoleListRequirement(new List<string>() { "SuperAdmin" }));
                }
            ));

            services.AddSingleton<IAuthorizationHandler, RoleListHandler>();






            //services.AddSingleton<IAuthorizationHandler, IsCEOAuthorizationHandler>();
            //services.AddSingleton<IAuthorizationHandler, HasVIPNumberAuthorizationHandler>();
            //services.AddSingleton<IAuthorizationHandler, IsAirlineEmployeeAuthorizationHandler>();
            //services.AddSingleton<IAuthorizationHandler, IsBannedAuthorizationHandler>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseMvc();
        }
    }

    public class IsVipRequirement : IAuthorizationRequirement
    {
        public IsVipRequirement(string airline)
        {
            Airline = airline;
        }

        public string Airline { get; }
    }

    public class IsCEOAuthorizationHandler : AuthorizationHandler<IsVipRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsVipRequirement requirement)
        {
            if (context.User.IsInRole("CEO"))
            {
                context.Succeed(requirement);
            }
            return Task.FromResult(0);
        }
    }

    public class HasVIPNumberAuthorizationHandler : AuthorizationHandler<IsVipRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsVipRequirement requirement)
        {
            if (context.User.IsInRole("SuperAdmin"))
            {
                context.Succeed(requirement);
            }

            if (context.User.HasClaim(claim => claim.Type == "VIPNumber"))
            {
                context.Succeed(requirement);
            }
            return Task.FromResult(0);
        }
    }

    public class IsAirlineEmployeeAuthorizationHandler : AuthorizationHandler<IsVipRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsVipRequirement requirement)
        {
            if (context.User.HasClaim(claim =>
                claim.Type == "EmployeeNumber" && claim.Issuer == requirement.Airline))
            {
                context.Succeed(requirement);
            }
            return Task.FromResult(0);
        }
    }

    public class IsBannedAuthorizationHandler : AuthorizationHandler<IsVipRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsVipRequirement requirement)
        {
            if (context.User.HasClaim(claim => claim.Type == "IsBannedFromVIP"))
            {
                context.Fail();
            }
            return Task.FromResult(0);
        }
    }
}
