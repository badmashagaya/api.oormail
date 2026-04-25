import { handleOtpRequest } from './otp_handler.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Route OTP, TOTP, and Household requests to the OTP handler
    if (url.pathname === "/otp" || url.pathname === "/prime-totp" || url.pathname === "/household") {
      return await handleOtpRequest(request);
    }

    // 2. Catch-all for any other routes
    return new Response(JSON.stringify({ error: "Endpoint not found." }), {
      status: 404,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }
};

