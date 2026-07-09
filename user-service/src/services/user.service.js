const logger = require("../config/logger");
const {redis} = require("../config/redis");

const getProfile = async( userId) =>{
    logger.info("First check in redis");
    const storedUser = await redis.get(`user:${userId}`);
    if(storedUser){
        logger.info("User found in redis");
        return JSON.parse(storedUser);
    }
    
    const user = await prisma.user.findUnique({
        where: { id: userId }
    });

    if(user){
        logger.info("User found in database, exclude password and cache in redis");
        const {password: _password, ... safeUser} = user;
        redis.set(`user:${userId}`, JSON.stringify(safeUser), 'EX', config.REDIS_USER_TTL);
        return safeUser;
    }

    logger.warn("User not found");
    return null;
}

module.exports = {
    getProfile
}