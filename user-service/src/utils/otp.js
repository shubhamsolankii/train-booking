
const {config} = require('../config');
const otpGenerator = require('otp-generator');
const {redis} = require('../config/redis');
const crypto = require('crypto');

const HMAC_SECRET = config.HMAC_SECRET || 'default_secret';
const RATE_MAX = parseInt(config.OTP_RATE_MAX_PER_HOUR || '5',10 )
const OTP_TTL = parseInt(config.OTP_TTL || '300', 10); // default 5 minutes

function hmacFor(email, otp){
   return crypto.createHmac('sha256', HMAC_SECRET).update(`${email}:${otp}`).digest('hex');
}

async function generateAndStoreOtp(meta){
    const rateKey = `otp:rate:${meta.email}`; 
    const sentCount = parseInt(await redis.get(rateKey) || '0', 10);

    if(sentCount >= RATE_MAX){
        throw new Error('OTP request limit exceeded. Please try again later.', "OTP_RATE_LIMIT");
    }

  
     const otp = otpGenerator.generate(6, {
          upperCaseAlphabets: false,
          lowerCaseAlphabets: false,
          specialChars: false
     })


    const otpSessionId = crypto.randomUUID();
    const hashed = hmacFor(meta.email, otp);
    await redis.set(`otp:session:${otpSessionId}`, JSON.stringify({hashed, meta}), 'EX', OTP_TTL || 300);
    await redis.incr(rateKey);
    await redis.expire(rateKey, 3600); // expire in 1 hour
    return {otp, otpSessionId};
}

module.exports = {
    generateAndStoreOtp
}