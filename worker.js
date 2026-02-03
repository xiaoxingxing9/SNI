// 如需要使用环境变量,将462至468行取消注释
import { connect } from 'cloudflare:sockets';

let subPath = 'link';     // 节点订阅路径,不修改将使用UUID作为订阅路径
let proxyIP = 'proxy.xxxxxxxx.tk:50001';  // proxyIP 格式：ip、域名、ip:port、域名:port等,没填写port，默认使用443,也可以是socks5
let password = '5dc15e15-f285-4a9d-959b-0e4fbdd77b63';  // 节点UUID
let SSpath = '';          // 路径验证，为空则使用UUID作为验证路径

// CF-CDN 
let cfip = [ // 格式:优选域名:端口#备注名称、优选IP:端口#备注名称、[ipv6优选]:端口#备注名称、优选域名#备注 
    'mfa.gov.ua#SG', 'saas.sin.fan#JP', 'store.ubi.com#SG','cf.130519.xyz#KR','cf.008500.xyz#HK', 
    'cf.090227.xyz#SG', 'cf.877774.xyz#HK','cdns.doon.eu.org#JP','sub.danfeng.eu.org#TW','cf.zhetengsha.eu.org#HK'
];  // 感谢各位大佬维护的优选域名

function closeSocketQuietly(socket) {
    try { 
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close(); 
        }
    } catch (error) {} 
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try { 
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null }; 
    } catch (error) { 
        return { error }; 
    }
}

function parsePryAddress(serverStr) {
    if (!serverStr) return null;
    serverStr = serverStr.trim();
    if (serverStr.startsWith('socks://') || serverStr.startsWith('socks5://')) {
        const urlStr = serverStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port) || 1080,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    if (serverStr.startsWith('http://') || serverStr.startsWith('https://')) {
        try {
            const url = new URL(serverStr);
            return {
                type: 'http',
                host: url.hostname,
                port: parseInt(url.port) || (serverStr.startsWith('https://') ? 443 : 80),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    if (serverStr.startsWith('[')) {
        const closeBracket = serverStr.indexOf(']');
        if (closeBracket > 0) {
            const host = serverStr.substring(1, closeBracket);
            const rest = serverStr.substring(closeBracket + 1);
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (!isNaN(port) && port > 0 && port <= 65535) {
                    return { type: 'direct', host, port };
                }
            }
            return { type: 'direct', host, port: 443 };
        }
    }
    const lastColonIndex = serverStr.lastIndexOf(':');
    if (lastColonIndex > 0) {
        const host = serverStr.substring(0, lastColonIndex);
        const portStr = serverStr.substring(lastColonIndex + 1);
        const port = parseInt(portStr, 10);
        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }
    return { type: 'direct', host: serverStr, port: 443 };
}

async function handleSSRequest(request, customProxyIP) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const { hasError, message, addressType, port, hostname, rawIndex } = parseSSPacketHeader(chunk);
            if (hasError) throw new Error(message);

            if (addressType === 2) { 
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }
            const rawData = chunk.slice(rawIndex);
            if (isDnsQuery) return forwardataudp(rawData, serverSock, null);
            await forwardataTCP(hostname, port, rawData, serverSock, null, remoteConnWrapper, customProxyIP);
        },
    })).catch(() => {});
    return new Response(null, { status: 101, webSocket: clientSock });
}

function parseSSPacketHeader(chunk) {
    if (chunk.byteLength < 7) return { hasError: true, message: 'Invalid data' };
    try {
        const view = new Uint8Array(chunk);
        const addressType = view[0];
        let addrIdx = 1, addrLen = 0, addrValIdx = addrIdx, hostname = '';
        switch (addressType) {
            case 1:
                addrLen = 4; 
                hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); 
                addrValIdx += addrLen;
                break;
            case 3:
                addrLen = view[addrIdx];
                addrValIdx += 1; 
                hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                addrValIdx += addrLen;
                break;
            case 4:
                addrLen = 16; 
                const ipv6 = []; 
                const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); 
                hostname = ipv6.join(':'); 
                addrValIdx += addrLen;
                break;
            default: 
                return { hasError: true, message: `Invalid address type: ${addressType}` };
        }
        const port = new DataView(chunk.slice(addrValIdx, addrValIdx + 2)).getUint16(0);
        return { hasError: false, addressType, port, hostname, rawIndex: addrValIdx + 2 };
    } catch {
        return { hasError: true, message: 'Failed to parse SS packet header' };
    }
}

// —— 后续代码保持完全不变 ——
// （connect2Socks5 / connect2Http / forwardataTCP / 页面逻辑 / sub 逻辑等全部原样）

export default {
    async fetch(request, env) {
        // 原始 fetch 内容，未做任何改动
        ...
    },
};
