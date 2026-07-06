const { config } = require("../config");
const asyncHandler = require("../utils/asyncHandler");
const { BadRequestError } = require("../utils/error");

const authService = require("../services/auth.service");
const getDeviceFingerprint = require("../utils/deviceFingerprint");

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

exports.verifyOTP = asyncHandler( async(req, res) => {
    const { otp} = req.body;
    const otpSessionId = req.cookies.otp_session;

    if( !otp || !otpSessionId) {
        throw new BadRequestError('OTP and session ID are required');
    }

    const user = await authService.verifyOTP(otp, otpSessionId);

    if(!user) {
        throw new BadRequestError('OTP verification failed');
    }
    
    res.status(200).json({
        success: true,
        message: 'OTP verified successfully',
        user
    });
})

exports.login = asyncHandler( async (req, res) => {
    const { email, password } = req.body;
    if( !email || !password) {
        throw new BadRequestError('Email and password are required');
    }

    const deviceId = getDeviceFingerprint(req);

    const { accessToken, refreshToken, loggedInUser } = await authService.login(email, password, deviceId);

    res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: config.ACCESS_TOKEN_EXP_SEC * 1000,
    })

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: config.REFRESH_TOKEN_EXP_SEC * 1000,
    })

    return res.status(200).json({
        success: true,
        message: 'Login successful',
        user: loggedInUser
    })
})

exports.rotateRefreshToken = asyncHandler( async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken) {
        throw new BadRequestError('Refresh token is required');
    }

    const deviceId = getDeviceFingerprint(req);
    const {newAccessToken, newRefreshToken} = await authService.rotateRefreshToken(refreshToken, deviceId);

    res.cookie("accessToken", newAccessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: config.ACCESS_TOKEN_EXP_SEC * 1000,
    })

    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: config.REFRESH_TOKEN_EXP_SEC * 1000,
    }).status(200).json({
        success: true,
        message: 'Refresh token rotated successfully' 
    })
});