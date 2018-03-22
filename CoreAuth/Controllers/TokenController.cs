using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace CoreAuth.Controllers
{
    [Produces("application/json")]
    [Route("api/Token")]
    public class TokenController : Controller
    {
        // {"UserName":"test", "Password":"test"}
        [HttpPost]
        public IActionResult Create([FromBody]UserCredentials request)
        {
            if (IsValidUserAndPasswordCombination(request.UserName, request.Password))
                return new ObjectResult(GenerateToken(request.UserName));
            return BadRequest();
        }

        private bool IsValidUserAndPasswordCombination(string username, string password)
        {
            return !string.IsNullOrEmpty(username) && username == password;
        }

        private string GenerateToken(string username)
        {

            //var claims = new[]
            //    {
            //        new Claim(ClaimTypes.Name, userCredentials.UserName),
            //        new Claim(ClaimTypes.Role, "SuperAdmin") 
            //    };

            //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.SecurityKey));
            //var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //var token = new JwtSecurityToken(
            //    issuer: _configuration.ValidIssuer,
            //    audience: _configuration.ValidAudience,
            //    claims: claims,
            //    expires: DateTime.Now.AddHours(_configuration.ExpireMinutes),
            //    signingCredentials: creds
            //);

            var claims = new Claim[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString()),
                new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.Now.AddDays(1)).ToUnixTimeSeconds().ToString()),
                new Claim(ClaimTypes.Role, "SuperAdmin")
            };

            var token = new JwtSecurityToken(
                new JwtHeader(new SigningCredentials(
                    new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes("the secret that needs to be at least 16 characeters long for HmacSha256")
                    ),
                    SecurityAlgorithms.HmacSha256
                )),
                new JwtPayload(claims)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public class UserCredentials
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}