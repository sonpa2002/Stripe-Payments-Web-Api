using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Stripe_Payments_Web_Api.Areas.Identity.Data;
using System.Text.Encodings.Web;
using System.Text;
using Microsoft.Extensions.Logging;
using Stripe_Payments_Web_Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Stripe_Payments_Web_Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly SignInManager<ApiUser> _signInManager;
        private readonly UserManager<ApiUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<AccountController> _logger;

        public AccountController(SignInManager<ApiUser> signInManager, UserManager<ApiUser> userManager, IEmailSender emailSender, ILogger<AccountController> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {

                var user = new ApiUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    // Đăng ký thành công
                    return Ok();
                }
                else
                {
                    // Xử lý lỗi đăng ký
                    return BadRequest(result.Errors);
                }
            }

            // Dữ liệu không hợp lệ
            return BadRequest(ModelState);
        }
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return Ok();
        }
            
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in.");

                // Tạo cookie xác thực
                //var token = GenerateJwtToken(user);
                //Response.Cookies.Append("jwtToken", token, new CookieOptions
                //{
                //    HttpOnly = true,
                //    Expires = DateTime.UtcNow.AddDays(7), // Thời gian hết hạn của cookie
                //    SameSite = SameSiteMode.Strict,
                //    Secure = true // Chỉ sử dụng cookie trên kênh an toàn (HTTPS)
                //});

                //Response.Cookies.Delete("jwtToken");
                return Ok();
            }
            if (result.RequiresTwoFactor)
            {
                // Redirect to two-factor authentication page
                return BadRequest("Yêu cầu xác thực hai yếu tố");
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                // Redirect to account lockout page
                return BadRequest("Tài khoản bị khóa");
            }
            return BadRequest("Đăng nhập không thành công");
        }
        //[HttpGet("logintest")]
        //public async Task<IActionResult> Logintest()
        //{
        //    LoginViewModel model = new LoginViewModel();
        //    model.Email = "sonll20@gmail.com"; model.Password = "123Abc;"; model.RememberMe = true;
        //    var user = await _userManager.FindByEmailAsync(model.Email);
        //    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
        //    if (result.Succeeded)
        //    {
        //        _logger.LogInformation("User logged in.");

        //        // Tạo cookie xác thực
        //        var token = GenerateJwtToken(user);
        //        Response.Cookies.Append("jwtToken", token, new CookieOptions
        //        {
        //            HttpOnly = true,
        //            Expires = DateTime.UtcNow.AddDays(7), // Thời gian hết hạn của cookie
        //            SameSite = SameSiteMode.Strict,
        //            Secure = true // Chỉ sử dụng cookie trên kênh an toàn (HTTPS)
        //        });
        //        //Response.Cookies.Delete("jwtToken");
        //        return Ok();
        //    }
        //    if (result.RequiresTwoFactor)
        //    {
        //        // Redirect to two-factor authentication page
        //        return BadRequest("Yêu cầu xác thực hai yếu tố");
        //    }
        //    if (result.IsLockedOut)
        //    {
        //        _logger.LogWarning("User account locked out.");
        //        // Redirect to account lockout page
        //        return BadRequest("Tài khoản bị khóa");
        //    }
        //    Console.WriteLine("Đăng nhập không thành công: " + result.ToString());

        //    return BadRequest("Đăng nhập không thành công");
        //}

        //private string GenerateJwtToken(ApiUser user)
        //{
        //    var tokenHandler = new JwtSecurityTokenHandler();
        //    var key = Encoding.ASCII.GetBytes("ThisIsTheSecureKey1234567890");
        //    var tokenDescriptor = new SecurityTokenDescriptor
        //    {
        //        Subject = new ClaimsIdentity(new[]
        //        {
        //    new Claim(ClaimTypes.NameIdentifier, user.Id),
        //    new Claim(ClaimTypes.Email, user.Email)
        //}),
        //        Expires = DateTime.UtcNow.AddDays(7), // Thời gian hết hạn của token
        //        Issuer = "APIUSER", // Giá trị Issuer khớp với cấu hình
        //        Audience = "https://payment.api.com", // Giá trị Audience khớp với cấu hình
        //        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        //    };
        //    var token = tokenHandler.CreateToken(tokenDescriptor);
        //    return tokenHandler.WriteToken(token);
        //}
        //
    }
}
