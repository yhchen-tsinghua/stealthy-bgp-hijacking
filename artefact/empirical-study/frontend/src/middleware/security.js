const { isPathAllowed } = require('../utils/paths');

module.exports = (req, res, next) => {
    const requestPath = req.path === '/' ? '/' : req.path.replace(/\/$/, '');

    if (isPathAllowed(requestPath)) {
        next();
    } else {
        res.status(403).send('403 Forbidden: Access Denied');
    }
};
