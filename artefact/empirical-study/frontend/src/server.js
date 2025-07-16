// src/server.js
const express = require('express');
const http = require('http');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const securityMiddleware = require('./middleware/security');
const { PORT, WEBPAGE_DIR } = require('./config');
const path = require('path');

const app = express();

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "https://cdn.jsdelivr.net"],
            "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "frame-src": ["https://docs.google.com"]
        }
    },
    hsts: {
        maxAge: 63072000, // 2 years in seconds
        includeSubDomains: true,
        preload: true
    }
}));

// Performance optimizations
app.use(compression({ level: 6 }));
app.use(morgan('combined'));

// Route configuration
app.use(securityMiddleware,
    express.static(WEBPAGE_DIR, {
        maxAge: '1y',
        etag: true,
        lastModified: true,
        index: 'index.html',
        redirect: false
    })
);

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Internal Server Error');
});

const server = http.createServer(app);
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Process event handlers
const exitHandler = (err) => {
    console.error('Fatal Error:', err);
    server.close(() => process.exit(1));
};

process.on('unhandledRejection', exitHandler);
process.on('uncaughtException', exitHandler);
