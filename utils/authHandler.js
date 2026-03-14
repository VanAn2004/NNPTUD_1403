let jwt = require('jsonwebtoken')
let userController = require("../controllers/users")
const fs = require('fs');
const path = require('path');

// Đọc public key từ file
const publicKey = fs.readFileSync(path.join(__dirname, '../keys/public.key'), 'utf8');

module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token || !token.startsWith('Bearer')) {
                return res.status(401).send("Ban chua dang nhap");
            }
            token = token.split(" ")[1];
            
            // Dùng thuật toán RS256 và publicKey để verify
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            
            let user = await userController.FindUserById(result.id);
            if (user) {
                req.user = user;
                next();
            } else {
                res.status(401).send("User khong ton tai");
            }
        } catch (error) {
            res.status(401).send("Token khong hop le hoac da het han");
        }
    }
}