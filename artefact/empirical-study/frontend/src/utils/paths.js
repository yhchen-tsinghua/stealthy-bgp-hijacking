const fs = require('fs');
const path = require('path');
const { WEBPAGE_DIR } = require('../config');

const allowedExtensions = new Set(['.js', '.html', '.css', '.json']);
const allowablePaths = new Set();

function populateAllowedPaths(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    entries.forEach(entry => {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            // Check if directory contains index.html
            const indexPath = path.join(fullPath, 'index.html');
            if (fs.existsSync(indexPath)) {
                const relativePath = path.relative(WEBPAGE_DIR, fullPath);
                allowablePaths.add(`/${relativePath}`);
            }
            populateAllowedPaths(fullPath);
        } else {
            const ext = path.extname(entry.name).toLowerCase();
            if (allowedExtensions.has(ext)) {
                const relativePath = path.relative(WEBPAGE_DIR, fullPath);
                allowablePaths.add(`/${relativePath}`);
            }
        }
    });
}

try {
    populateAllowedPaths(WEBPAGE_DIR);
    // Add root path if index.html exists
    if (fs.existsSync(path.join(WEBPAGE_DIR, 'index.html'))) {
        allowablePaths.add('/');
    }
} catch (err) {
    console.error('Error initializing allowed paths:', err);
    process.exit(1);
}

module.exports = {
    isPathAllowed: (requestedPath) => {
        const normalizedPath = requestedPath.replace(/\/$/, '') || '/';
        return allowablePaths.has(normalizedPath);
    },
};
