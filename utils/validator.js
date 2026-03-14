const { body, validationResult } = require('express-validator');

// Hàm validate trả về kết quả
const validatedResult = (req, res, next) => {
    let result = validationResult(req);
    if (!result.isEmpty()) {
        return res.status(400).send(result.array().map(e => ({
            [e.path]: e.msg
        })));
    }
    next();
};

module.exports = {
    validatedResult,

    ChangePasswordValidator: [
        body('oldPassword').notEmpty().withMessage('Vui lòng nhập mật khẩu cũ'),
        body('newPassword')
            .isLength({ min: 8 }).withMessage('Mật khẩu mới phải có ít nhất 8 ký tự')
            .custom((value, { req }) => {
                if (value === req.body.oldPassword) {
                    throw new Error('Mật khẩu mới không được trùng với mật khẩu cũ');
                }
                return true;
            })
    ],

    CreateUserValidator: [
        body("email").notEmpty().withMessage("email khong duoc de trong").bail().isEmail().withMessage("email sai dinh dang"),
        body("username").notEmpty().withMessage("username khong duoc de trong").bail().isAlphanumeric().withMessage("username khong duoc chua ki tu dac biet"),
        body("password").notEmpty().withMessage("password khong duoc de trong").bail().isStrongPassword({
            minLength: 8, minLowercase: 1, minNumbers: 1, minSymbols: 1, minUppercase: 1
        }).withMessage("password dai it nhat 8 ki tu, trong do co it nhat 1 ki tu hoa, 1 ki tu thuong, 1 ki tu so va 1 ki tu dac biet"),
        body("role").notEmpty().withMessage("role khong duoc de trong").bail().isMongoId().withMessage("role phai la 1 id"),
        body("avatarUrl").optional().isArray().withMessage("image khong hop le"),
        body("avatarUrl.*").optional().isURL().withMessage("Url khong hop le")
    ],

    RegisterValidator: [
        body("email").notEmpty().withMessage("email khong duoc de trong").bail().isEmail().withMessage("email sai dinh dang"),
        body("username").notEmpty().withMessage("username khong duoc de trong").bail().isAlphanumeric().withMessage("username khong duoc chua ki tu dac biet"),
        body("password").notEmpty().withMessage("password khong duoc de trong").bail().isStrongPassword({
            minLength: 8, minLowercase: 1, minNumbers: 1, minSymbols: 1, minUppercase: 1
        }).withMessage("password dai it nhat 8 ki tu, trong do co it nhat 1 ki tu hoa, 1 ki tu thuong, 1 ki tu so va 1 ki tu dac biet")
    ],

    ModifyUserValidator: [
        body("email").isEmpty().withMessage("email khong duoc thay doi"),
        body("username").isEmpty().withMessage("username khong duoc thay doi"),
        body("password").optional().isStrongPassword({
            minLength: 8, minLowercase: 1, minNumbers: 1, minSymbols: 1, minUppercase: 1
        }).withMessage("password dai it nhat 8 ki tu, trong do co it nhat 1 ki tu hoa, 1 ki tu thuong, 1 ki tu so va 1 ki tu dac biet"),
        body("role").isEmpty().withMessage("role khong duoc thay doi"),
        body("avatarUrl").optional().isArray().withMessage("image khong hop le"),
        body("avatarUrl.*").optional().isURL().withMessage("Url khong hop le")
    ]
};