// Importing all Neccessary Packages //
import express from 'express';
import cors from 'cors';
import { createConnection } from 'net';
import axios from 'axios';
import { load } from 'cheerio';
import dns from 'dns/promises';
import { URL } from 'url';

// Declaring App Variable Express //
const application = express();

// All Middlewares Starts Here //
application.use(cors());
application.use(express.json());
// All Middlewares Ends Here //

// Running the application //
application.get('/', async (request, response) => { response.send({ domainInformation: await getDomainWhoisInfo(request.query?.q as string), allSubDomains: await getSubdomainsInfo(request.query?.q as string) }) });
application.listen(80);
// All Helper Functions //
async function getDomainWhoisInfo(DomainName: string): Promise<{ DomainName: string; RegistryDomainId: string; RegistrarWhoisServer: string; RegistrarUrl: string; UpdatedDate: string; CreationDate: string; RegistryExpiryDate: string; Registrar: string; RegistrarIanaId: string; RegistrarAbuseEmail: string; RegistrarAbusePhone: string; DomainStatus: string[]; NameServer: string[]; Dnssec: string; } | null> {
    let DomainWhoisInformation: { DomainName: string; RegistryDomainId: string; RegistrarWhoisServer: string; RegistrarUrl: string; UpdatedDate: string; CreationDate: string; RegistryExpiryDate: string; Registrar: string; RegistrarIanaId: string; RegistrarAbuseEmail: string; RegistrarAbusePhone: string; DomainStatus: string[]; NameServer: string[]; Dnssec: string; } = {
        DomainName: '',
        RegistryDomainId: '',
        RegistrarWhoisServer: '',
        RegistrarUrl: '',
        UpdatedDate: '',
        CreationDate: '',
        RegistryExpiryDate: '',
        Registrar: '',
        RegistrarIanaId: '',
        RegistrarAbuseEmail: '',
        RegistrarAbusePhone: '',
        DomainStatus: [],
        NameServer: [],
        Dnssec: ''
    };

    // Define the WHOIS server for different TLDs
    let server: string = 'whois.verisign-grs.com:43'; // Default for .com
    if (DomainName.endsWith('.org')) {
        server = 'whois.pir.org:43';
    } else if (DomainName.endsWith('.net')) {
        server = 'whois.verisign-grs.net:43';
    }

    const [hostname, port] = server.split(':');

    return new Promise((resolve, reject) => {
        // Create a TCP connection to the WHOIS server
        const conn = createConnection({ host: hostname, port: parseInt(port) }, () => {
            // Send the WHOIS query to the WHOIS server
            conn.write(DomainName + '\r\n');
        });

        let responseData = '';

        // Collect data from the server
        conn.on('data', (data) => {
            responseData += data.toString();
        });

        // Handle the response end
        conn.on('end', () => {
            // Split the WHOIS response by lines
            const lines = responseData.split('\n');

            // Define regex for matching key-value pairs in the WHOIS data
            const keyVal = /^\s*([^:]+):\s*(.+)$/;

            // Process each line in the response
            for (let line of lines) {
                line = line.trim();
                if (!line) continue;

                const match = line.match(keyVal);
                if (match) {
                    const key = match[1].trim();
                    const val = match[2].trim();

                    // Map the key to the corresponding field in the response object
                    switch (key) {
                        case 'Domain Name':
                            DomainWhoisInformation.DomainName = val;
                            break;
                        case 'Registry Domain ID':
                            DomainWhoisInformation.RegistryDomainId = val;
                            break;
                        case 'Registrar WHOIS Server':
                            DomainWhoisInformation.RegistrarWhoisServer = val;
                            break;
                        case 'Registrar URL':
                            DomainWhoisInformation.RegistrarUrl = val;
                            break;
                        case 'Updated Date':
                            DomainWhoisInformation.UpdatedDate = val;
                            break;
                        case 'Creation Date':
                            DomainWhoisInformation.CreationDate = val;
                            break;
                        case 'Registry Expiry Date':
                            DomainWhoisInformation.RegistryExpiryDate = val;
                            break;
                        case 'Registrar':
                            DomainWhoisInformation.Registrar = val;
                            break;
                        case 'Registrar IANA ID':
                            DomainWhoisInformation.RegistrarIanaId = val;
                            break;
                        case 'Registrar Abuse Contact Email':
                            DomainWhoisInformation.RegistrarAbuseEmail = val;
                            break;
                        case 'Registrar Abuse Contact Phone':
                            DomainWhoisInformation.RegistrarAbusePhone = val;
                            break;
                        case 'Domain Status':
                            DomainWhoisInformation.DomainStatus.push(val);
                            break;
                        case 'Name Server':
                            DomainWhoisInformation.NameServer.push(val);
                            break;
                        case 'DNSSEC':
                            DomainWhoisInformation.Dnssec = val;
                            break;
                        default:
                            break;
                    }
                }
            }

            // If no DomainName was found, reject the promise
            if (!DomainWhoisInformation.DomainName) {
                resolve(null);
            } else {
                resolve(DomainWhoisInformation);
            }
        });

        // Handle connection errors
        conn.on('error', (err) => {
            reject(`Connection error: ${err.message}`);
        });
    });
}
async function getSubdomainsInfo(domainName: string): Promise<{ issuer_ca_id: number; issuer_name: string; common_name: string; name_value: string; id: number; entry_timestamp: string; not_before: string; not_after: string; serial_number: string; result_count: number; http_data: string | null; wayback_urls: string[] | null; }[] | null> {
    try {
        const response = await axios.get(`https://crt.sh/?q=${domainName}&output=json`, { timeout: 9600000 });
        if (response.data.length === 0) {
            return null;
        }
        const certs = response.data;
        const seen = new Set();
        const results = [];
        for (const cert of certs) {
            const subdomain = cert.name_value.split('\n')[0];
            if (!seen.has(subdomain)) {
                seen.add(subdomain);
                // Fetch both HTTP and Wayback data
                const [httpData, waybackURLs] = await Promise.all([
                    getHttpData(subdomain),       // already defined elsewhere
                    getWayBackURLs(subdomain)
                ]);
                results.push({
                    ...cert,
                    http_data: httpData,
                    wayback_urls: waybackURLs
                });
            }
        }
        return results;
    } catch { return null; }
}
export async function getHttpData(domain: string): Promise<string | null> {
    try {
        const response = await axios.get(`https://${domain}`, { timeout: 10000, maxRedirects: 0, validateStatus: status => status >= 200 && status < 400 });

        const body = response.data;
        const contentLength = Buffer.byteLength(body, 'utf8');
        const contentType = response.headers['content-type'] || 'Unknown Type';
        const server = response.headers['server'] || 'Unknown Server';
        const statusCode = response.status;

        // Extract title using cheerio (like html tokenizer)
        const $ = load(body);
        const title = $('title').first().text().trim() || 'No Title';

        // Resolve IP
        let ip = 'N/A';
        try {
            const parsed = new URL(`https://${domain}`);
            const result = await dns.lookup(parsed.hostname);
            ip = result.address;
        } catch (err) {
            ip = 'IP Lookup Failed';
        }

        return `${title} [${statusCode}] [${contentType}] [CL: ${contentLength}] [IP: ${ip}] [Server: ${server}]`;

    } catch { return null }
}
async function getWayBackURLs(domain: string): Promise<string[] | null> {
    const response = await axios.get(`http://web.archive.org/cdx/search/cdx?url=${domain}*&output=json&collapse=urlkey`, { timeout: 10000, maxRedirects: 0, validateStatus: status => status >= 200 && status < 400 });
    const ReturnData: string[] = [];
    (response.data as []).slice(1).forEach(element => { ReturnData.push(element[5] as string) })
    return ReturnData
}