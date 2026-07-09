
const asyncHandler = require('../utils/asyncHandler');
const { BadRequestError } = require('../utils/error');
const userService = require('../services/user.service');

exports.getProfile = asyncHandler( async(req, res) =>{
    const userId = req.user.id;

    if(!userId){
        throw new BadRequestError("User ID is required");
    }

    const user = await userService.getProfile(userId);

    return res.status(200).json({
        success: true,
        message: "User profile retrieved successfully",
        data: {user}
    });
})