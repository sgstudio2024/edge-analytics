// 入口文件：根据环境变量决定使用中文或英文版本
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Main entry file for Cloudflare Analytics server
// This file dynamically imports either the Chinese (default) or English version
// based on the USE_ENGLISH environment variable

if (process.env.USE_ENGLISH === 'true') {
    console.log('Loading English version...');
    import('./index_EN.js');
} else {
    console.log('Loading Chinese version (default)...');
    import('./index.js');
}
