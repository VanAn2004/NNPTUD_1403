let express = require('express')
let router = express.Router()
let userController = require('../controllers/users')
let { RegisterValidator, validatedResult } = require('../utils/validator')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
const { check } = require('express-validator')
const { checkLogin } = require('../utils/authHandler')
const { ChangePasswordValidator } = require('../utils/validator');

router.post('/change-password', checkLogin, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    try {
        let { oldPassword, newPassword } = req.body;
        let user = req.user;

        // Kiểm tra mật khẩu cũ (Sử dụng compare async)
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).send({ message: "Mật khẩu cũ không chính xác" });
        }

        // Hash mật khẩu mới (Sử dụng hash async)
        user.password = await bcrypt.hash(newPassword, 10);

        // Lưu vào DB
        await user.save();

        res.send({ message: "Đổi mật khẩu thành công" });
    } catch (error) {
        next(error);
    }
});

router.post('/register', RegisterValidator, validatedResult, async function (req, res, next) {
    let { username, password, email } = req.body;
    let newUser = await userController.CreateAnUser(
        username, password, email, '69b2763ce64fe93ca6985b56'
    )
    res.send(newUser)
})
router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let user = await userController.FindUserByUsername(username);
    if (!user) {
        res.status(404).send({
            message: "thong tin dang nhap khong dung"
        })
        return;
    }
    if (!user.lockTime || user.lockTime < Date.now()) {
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save();
            // Đọc private key từ file
            const fs = require('fs');
            const path = require('path');
            const privateKey = fs.readFileSync(path.join(__dirname, '../keys/private.key'));
            let token = jwt.sign({
                id: user._id,
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '1h'
            });
            res.send(token)
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = new Date(Date.now() + 60 * 60 * 1000)
            }
            await user.save();
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }
    } else {
        res.status(404).send({
            message: "user dang bi ban"
        })
    }

})
router.get('/me',checkLogin, function (req,res,next) {
    res.send(req.user)
})

module.exports = router;