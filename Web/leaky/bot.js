const puppeteer = require('puppeteer');
const fs = require('fs');
const crypto = require('crypto');

let FLAG;
try {
    FLAG = fs.readFileSync('/flag.txt', 'utf8').trim();
} catch (error) {
    FLAG = "ZeroDays{fake_flag}";
}

console.log("Bot started");

function generateRandomString(length = 16) {
    return crypto.randomBytes(length).toString('hex');
}

const browserArgs = {
    headless: true,
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser',
    args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer'
    ]
};

module.exports = {
    visit: async (urlToVisit) => {
        const browser = await puppeteer.launch(browserArgs);
        try {
            const page = await browser.newPage();
            
            await page.goto('http://localhost:3000/register', { waitUntil: 'networkidle0' });
            
            const username = generateRandomString(12);
            const password = generateRandomString(16);
            
            console.log(`Registering user: ${username} with password: ${password}`);
            await page.type('#username', username);
            await page.type('#password', password);
            await page.click('button[type="submit"]');
            await page.waitForNavigation({ waitUntil: 'networkidle0' });

            console.log("Saving flag...")
            await page.type('#title', 'FLAG');
            await page.type('#content', FLAG);
            await page.click('.add-button');
            await page.waitForNavigation({ waitUntil: 'networkidle0' });
            
            console.log(`Bot visiting ${urlToVisit}`);
            await page.goto(urlToVisit, { waitUntil: 'networkidle0' });
            
            console.log("Waiting 60 seconds...");
            await new Promise(resolve => setTimeout(resolve, 60000));
            
            console.log("Bot completed successfully");
            return true;
            
        } catch (error) {
            console.error('Bot error:', error);
            return false;
        } finally {
            await browser.close();
        }
    }
}; 