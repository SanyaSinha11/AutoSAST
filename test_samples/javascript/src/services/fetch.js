const axios = require('axios');
const url = require('url');

const ALLOWED_HOSTS = ['api.internal.acme.com', 'cdn.acme.com'];
const BLOCKED_IPS = ['127.0.0.1', '0.0.0.0', '169.254.169.254'];

async function fetchRemote(targetUrl) {
    const response = await axios.get(targetUrl);
    return response.data;
}

async function fetchInternal(targetUrl) {
    const parsed = url.parse(targetUrl);
    
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Invalid protocol');
    }
    
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
        throw new Error('Host not allowed');
    }
    
    const response = await axios.get(targetUrl);
    return response.data;
}

async function fetchWithRedirect(targetUrl) {
    const response = await axios.get(targetUrl, {
        maxRedirects: 5
    });
    return response.data;
}

async function fetchStrict(targetUrl) {
    const parsed = url.parse(targetUrl);
    
    if (BLOCKED_IPS.includes(parsed.hostname)) {
        throw new Error('Blocked IP');
    }
    
    if (!parsed.hostname.endsWith('.acme.com')) {
        throw new Error('External host not allowed');
    }
    
    const response = await axios.get(targetUrl, {
        maxRedirects: 0,
        validateStatus: (status) => status < 400
    });
    return response.data;
}

module.exports = {
    fetchRemote,
    fetchInternal,
    fetchWithRedirect,
    fetchStrict
};

