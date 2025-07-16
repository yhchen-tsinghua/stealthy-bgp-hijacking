// src/config.js
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

module.exports = {
    PORT: process.env.PORT || 3000,
    WEBPAGE_DIR: path.join(__dirname, '..', 'public', 'webpage'),
};
