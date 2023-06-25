using Microsoft.AspNetCore.Http;

namespace Stripe_Payments_Web_Api
{
    public class JwtTokenMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtTokenMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            // Kiểm tra xem token có tồn tại trong cookie không
            if (context.Request.Cookies.TryGetValue("jwtToken", out var token))
            {
                // Thêm token vào tiêu đề Authorization
                context.Request.Headers.Add("Authorization", "Bearer " + token);

                //Console.WriteLine(context.Request);
            }
            // Chuyển tiếp yêu cầu cho middleware tiếp theo trong pipeline
            await _next(context);
        }
    }
}
