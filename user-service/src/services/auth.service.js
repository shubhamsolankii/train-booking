const prisma = require("../config/prisma")
const { ConflictError, BadRequestError } = require("../utils/error");
const { verifyOtp } = require("../utils/otp");
const { generateAndStoreOtp } = require("../utils/otp");
// const { sendOtpEmail } = require("../utils/email");
const bycrypt = require("bcrypt");


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

module.exports = {
    sendOTP,
    verifyOTP
}