using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Stripe_Payments_Web_Api.Contracts;
using Stripe_Payments_Web_Api.Models;
using Stripe_Payments_Web_Api.Models.Stripe;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.Extensions.Logging;

namespace Stripe_Payments_Web_Api.Controllers
{
    [Route("api/[controller]")]
    public class StripeController : Controller
    {
        private readonly IStripeAppService _stripeService;
        private readonly ILogger<AccountController> _logger;

        public StripeController( IStripeAppService stripeService, ILogger<AccountController> logger)
        {
            _stripeService = stripeService;
            _logger = logger;
        }
        //
        [Authorize]
        [HttpGet("test")]
        public async Task<string> Test()
        {
            return "API is up and running!";
        }
        [HttpGet("testcookie")]
        public async Task<string> TestCookie()
        {
            string cookieValue = Request.Cookies[".AspNetCore.Identity.Application"];
            if (cookieValue == null)
                cookieValue = "null ne";
            // Trả về giá trị cookie
            return cookieValue;
        }
        //
        [HttpPost("customer/add")]
        public async Task<ActionResult<StripeCustomer>> AddStripeCustomer(
            [FromBody] AddStripeCustomer customer,
            CancellationToken ct)
        {
            StripeCustomer createdCustomer = await _stripeService.AddStripeCustomerAsync(
                customer,
                ct);

            return StatusCode(StatusCodes.Status200OK, createdCustomer);
        }

        [HttpPost("payment/add")]
        public async Task<ActionResult<StripePayment>> AddStripePayment(
            [FromBody] AddStripePayment payment,
            CancellationToken ct)
        {
            StripePayment createdPayment = await _stripeService.AddStripePaymentAsync(
                payment,
                ct);

            return StatusCode(StatusCodes.Status200OK, createdPayment);
        }
    }
}

