const jwt = require('jsonwebtoken');

// Middleware para verificar o token JWT
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado!' });
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret, (err, decoded) => {
            if (err) {
                return res.status(400).json({ msg: 'Token inválido!' });
            }
            req.userId = decoded.id;
            next();
        });
    } catch (error) {
        res.status(400).json({ msg: "Token inválido" });
    }
}

module.exports = checkToken;
