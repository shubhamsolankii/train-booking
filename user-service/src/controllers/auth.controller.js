const { config } = require("../config");
const asyncHandler = require("../utils/asyncHandler");
const { BadRequestError } = require("../utils/error");

const authService = require("../services/auth.service");

exports.sendOTP = asyncHandler(async (req, res) => {
    const { firstName, lastName, email, password, confirmPassword } = req.body;

    if( !firstName || !lastName || !email || !password || !confirmPassword) {
        throw new BadRequestError('Please provide all required fields');
    }

    if( password !== confirmPassword) {
        throw new BadRequestError('Passwords do not match');
    }

     const {otpSessionId, otp} = await authService.sendOTP( firstName, lastName, email, password );

     res.cookie("otp_session", otpSessionId, {
         httpOnly: true,
         secure: true,
         sameSite: 'Strict',
         maxAge: config.OTP_TTL * 1000, // 5 minutes
     }).status(200).json({
         success: true,
         message: 'OTP sent successfully',
         otpSessionId,
         otp
     })
})