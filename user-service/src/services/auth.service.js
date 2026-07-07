const { config } = require("../config");
const {redis} = require("../config/redis");
const prisma = require("../config/prisma");
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require("../utils/auth");
const { ConflictError, BadRequestError, UnauthorizedError } = require("../utils/error");
const { verifyOtp } = require("../utils/otp");
const { generateAndStoreOtp } = require("../utils/otp");
// const { sendOtpEmail } = require("../utils/email");
const bycrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(config.GOOGLE_CLIENT_ID);

const sendOTP = async( firstName, lastName, email, password) => {

    const existingUser = await prisma.user.findUnique({
        where : {
            email : email
        }
    })

    if(existingUser) {
        throw new ConflictError('User with this email already exists');
    }

    const hashedPassword = await bycrypt.hash(password, 12);
    const meta = { firstName, lastName, email, hashedPassword };
    const {otp, otpSessionId} = await generateAndStoreOtp(meta);

    // await sendOtpEmail(email, otp);
    return {otpSessionId, otp}
}

const verifyOTP = async(otp, otpSessionId) => {
    const meta = await verifyOtp(otp, otpSessionId);

    if(!meta) {
        throw new BadRequestError('OTP verification failed');
    }

    const user = await prisma.user.create({
        data : {
            firstName : meta.firstName,
            lastName : meta.lastName,
            email : meta.email,
            password : meta.hashedPassword
        }
    });

    //await verifyOtpEmail(otp, otpSessionId); 
    return user;
}

const login = async( email, password, deviceId) => {
    const existingUser = await prisma.user.findUnique({
        where:{
            email
        }
    })

    if(!existingUser){
        throw new BadRequestError('Invalid email or password');
    }

    const doesPasswordMatch = await bycrypt.compare(password,existingUser.password);
    if(!doesPasswordMatch){
        throw new BadRequestError('Passwords do not match');
    }

    const accessToken = generateAccessToken(existingUser.id);
    const refreshToken = generateRefreshToken(existingUser.id);

    const {jti} = jwt.decode(refreshToken);
    await redis.set(`refresh:${existingUser.id}:${deviceId}`, jti, 'EX', config.REFRESH_TOKEN_EXP_SEC);
    const {password: _password, ... safeUser} = existingUser;
    await redis.set(`user:${existingUser.id}`, JSON.stringify(safeUser), 'EX', config.REDIS_USER_TTL);
    return {accessToken, refreshToken, loggedInUser: safeUser};
}

const rotateRefreshToken = async(refreshToken, deviceId) => {
    const payload = verifyRefreshToken(refreshToken);
    const {id: userId, jti} = payload;

    const storedJti = await redis.get(`refresh:${userId}:${deviceId}`); 

    if(!storedJti) {
        throw new BadRequestError('Invalid refresh token JTI NOT FOUND');
    }

    if(storedJti !== jti) {
        await redis.del(`refresh:${userId}:${deviceId}`);
        throw new BadRequestError('Invalid refresh token JTI MISMATCH. Possible token reuse detected');
    }

    const newAccessToken = generateAccessToken(payload.id);
    const newRefreshToken = generateRefreshToken(payload.id);
    const {jti: newJti} = jwt.decode(newRefreshToken);
    await redis.set(`refresh:${payload.id}:${deviceId}`, newJti, 'EX', config.REFRESH_TOKEN_EXP_SEC);
    return {newAccessToken, newRefreshToken};
}

const verifyGoogleIdToken = async(idToken, deviceId) => {

    const ticket = await client.verifyIdToken({
        idToken,
        audience: config.GOOGLE_CLIENT_ID,
    })

    const payload = ticket.getPayload();

    if(!payload.sub || !payload.email){
        throw new UnauthorizedError("Invalid Google ID token");
    }

    const googleUser =  {
        provider: payload.iss,
        providerId: payload.sub,
        email: payload.email,
        firstName: payload.given_name,
        lastName: payload.family_name,
        emailVerified: payload.email_verified || false,
    }

    const user = await prisma.$transaction( async (tx) => {
        let googleAuth = await tx.authProvider.findUnique({
            where:{
                provider_providerId: {
                    provider: googleUser.provider,
                    providerId: googleUser.providerId 
                }
            },
            include: {user: true}
        })

        if(googleAuth){
             return googleAuth.user;
        }

        let existingUser = await tx.user.findUnique({
            where: {email: googleUser.email}
        })

        if(existingUser){
            await tx.authProvider.create({
                data:{
                    provider: googleUser.provider,
                    providerId: googleUser.providerId,
                    userId: existingUser.id

                }
            })

            return existingUser;
        }

        return await tx.user.create({
            data:{
                 email: googleUser.email,
                 firstName: googleUser.firstName,
                 lastName: googleUser.lastName,
                 emailVerified: googleUser.emailVerified,
                 AuthProviders:{
                    create:{
                        provider: googleUser.provider,
                        providerId: googleUser.providerId
                    }
                 }
            }
        })
    })

    const {jti} = jwt.decode(refreshToken);
    await redis.set(`refresh:${user.id}:${deviceId}`, jti, 'EX', config.REFRESH_TOKEN_EXP_SEC);
    const {password: _password, ... safeUser} = user;
    await redis.set(`user:${user.id}`, JSON.stringify(safeUser), 'EX', config.REDIS_USER_TTL);

     const accessToken = generateAccessToken(user.id);
     const refreshToken = generateRefreshToken(user.id);
     return {accessToken, refreshToken, loggedInUser: safeUser};
}


module.exports = {
    sendOTP,
    verifyOTP,
    login,
    rotateRefreshToken,
    verifyGoogleIdToken
}