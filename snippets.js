import { connect } from 'cloudflare:sockets';
const uuid = "ff594501-2b04-4da8-b554-059e62b12204", aiProxyip = String.fromCharCode(104, 75, 103, 97, 105, 46, 53, 56, 56, 48, 55, 46, 68, 69, 53, 46, 78, 69, 116), proxyHost = String.fromCharCode(112, 82, 111, 88, 89, 46, 90, 106, 99, 108, 79, 117, 68, 46, 85, 83, 46, 99, 73), textEncoder = new TextEncoder, textDecoder = new TextDecoder, _h = c => c > 64 ? 9 + (7 & c) : 15 & c, _b = p => _h(uuid.charCodeAt(p)) << 4 | _h(uuid.charCodeAt(p + 1)), U0 = _b(0), U1 = _b(2), U2 = _b(4), U3 = _b(6), U4 = _b(9), U5 = _b(11), U6 = _b(14), U7 = _b(16), U8 = _b(19), U9 = _b(21), U10 = _b(24), U11 = _b(26), U12 = _b(28), U13 = _b(30), U14 = _b(32), U15 = _b(34), binaryAddrToString = (addrType, addrBytes) => {
  if (3 === addrType) return addrBytes.length <= 64 ? String.fromCharCode.apply(null, addrBytes) : textDecoder.decode(addrBytes);
  if (1 === addrType) return `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
  let ipv6 = (addrBytes[0] << 8 | addrBytes[1]).toString(16);
  for (let i = 1; i < 8; i++) ipv6 += ":" + (addrBytes[2 * i] << 8 | addrBytes[2 * i + 1]).toString(16);
  return `[${ipv6}]`;
}, parseHostPort = (addr, defaultPort) => {
  let idx, host = addr, port = defaultPort;
  return 91 === addr.charCodeAt(0) ? -1 !== (idx = addr.indexOf("]:")) && (host = addr.substring(0, idx + 1), 
  port = addr.substring(idx + 2)) : -1 !== (idx = addr.indexOf(".tp")) && -1 === addr.lastIndexOf(":") ? port = addr.substring(idx + 3, addr.indexOf(".", idx + 3)) : -1 !== (idx = addr.lastIndexOf(":")) && (host = addr.substring(0, idx), 
  port = addr.substring(idx + 1)), [host, (port = parseInt(port), isNaN(port) ? defaultPort : port)];
};
const createConnect = (hostname, port, socketOptions, socket = connect({hostname: hostname, port: port}, socketOptions)) => socket.opened.then(() => socket), dohJsonHeaders = {headers: {accept: "application/dns-json"}}, aiDomains = ["chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "chat.com", "claude.ai", "claude.com", "anthropic.com", "grok.com", "x.ai", "perplexity.ai", "poe.com", "character.ai", "pi.ai", "you.com", "phind.com", "blackbox.ai", "civitai.com"].map(d => textEncoder.encode(d)), isAiDomain = (addrBytes, addrType) => {
  if (3 !== addrType || !addrBytes) return !1;
  let len = addrBytes.length;
  len > 0 && 46 === addrBytes[len - 1] && len--;
  for (let i = 0; i < aiDomains.length; i++) {
    const d = aiDomains[i], dLen = d.length;
    if (len < dLen) continue;
    if (len > dLen && 46 !== addrBytes[len - dLen - 1]) continue;
    let match = !0;
    const offset = len - dLen;
    for (let j = 0; j < dLen; j++) {
      const c = addrBytes[offset + j];
      if ((c >= 65 && c <= 90 ? c + 32 : c) !== d[j]) {
        match = !1;
        break;
      }
    }
    if (match) return !0;
  }
  return !1;
}, parseProtocolChunk = chunk => {
  const len = chunk.length, result = {success: !1, needMore: !1, handshake: null, parsedRequest: null};
  if (len >= 17 && chunk[1] === U0 && chunk[2] === U1 && chunk[3] === U2 && chunk[4] === U3 && chunk[5] === U4 && chunk[6] === U5 && chunk[7] === U6 && chunk[8] === U7 && chunk[9] === U8 && chunk[10] === U9 && chunk[11] === U10 && chunk[12] === U11 && chunk[13] === U12 && chunk[14] === U13 && chunk[15] === U14 && chunk[16] === U15) {
    if (len < 18) return result.needMore = !0, result;
    const offset = 19 + chunk[17];
    if (len < offset + 4) return result.needMore = !0, result;
    let addrType = chunk[offset + 2];
    1 !== addrType && (addrType += 1);
    let addrLen = 3 === addrType ? offset + 3 < len ? chunk[offset + 3] : null : 1 === addrType ? 4 : 4 === addrType ? 16 : -1;
    if (null === addrLen) return result.needMore = !0, result;
    if (addrLen > 0) {
      let addrOffset = 3 === addrType ? offset + 4 : offset + 3;
      const dataOffset = addrOffset + addrLen;
      if (len < dataOffset) return result.needMore = !0, result;
      const port = chunk[offset] << 8 | chunk[offset + 1], sni = ((chunk, addrType, addrOffset, addrLen, dataOffset) => {
        if (3 !== addrType && dataOffset < chunk.length) {
          const sniRes = (data => {
            if (!data || 0 === data.length) return null;
            if (22 !== data[0]) return null;
            if (data.length < 5) return {needMore: !0};
            const recordLen = data[3] << 8 | data[4];
            if (data.length < 5 + recordLen) return {needMore: !0};
            if (1 !== data[5]) return null;
            let offset = 43;
            if (offset >= data.length) return {needMore: !0};
            if (offset += 1 + data[offset], offset + 2 > data.length) return {needMore: !0};
            if (offset += 2 + (data[offset] << 8 | data[offset + 1]), offset >= data.length) return {needMore: !0};
            if (offset += 1 + data[offset], offset + 2 > data.length) return null;
            const extLen = data[offset] << 8 | data[offset + 1];
            offset += 2;
            const extEnd = offset + extLen;
            if (extEnd > data.length) return {needMore: !0};
            for (;offset + 4 <= extEnd; ) {
              const extType = data[offset] << 8 | data[offset + 1], len = data[offset + 2] << 8 | data[offset + 3];
              if (offset += 4, 0 === extType) {
                let sniOffset = offset + 2;
                const sniEnd = offset + len;
                for (;sniOffset + 3 <= sniEnd; ) {
                  const nameType = data[sniOffset], nameLen = data[sniOffset + 1] << 8 | data[sniOffset + 2];
                  if (sniOffset += 3, 0 === nameType) return sniOffset + nameLen <= sniEnd ? {offset: sniOffset, len: nameLen} : {needMore: !0};
                  sniOffset += nameLen;
                }
              }
              offset += len;
            }
            return null;
          })(chunk.subarray(dataOffset));
          if (sniRes?.needMore) return {addrType: addrType, addrOffset: addrOffset, addrLen: addrLen, isAiDomain: isAiDomain(chunk.subarray(addrOffset, addrOffset + addrLen), addrType), needMore: !0};
          if (sniRes?.len) {
            const sniOffset = dataOffset + sniRes.offset, sniBytes = chunk.subarray(sniOffset, sniOffset + sniRes.len);
            return {addrType: addrType, addrOffset: addrOffset, addrLen: addrLen, isAiDomain: isAiDomain(sniBytes, 3), needMore: !1};
          }
        }
        return {addrType: addrType, addrOffset: addrOffset, addrLen: addrLen, isAiDomain: isAiDomain(chunk.subarray(addrOffset, addrOffset + addrLen), addrType), needMore: !1};
      })(chunk, addrType, addrOffset, addrLen, dataOffset);
      if (sni.needMore) return result.needMore = !0, result;
      addrType = sni.addrType, addrOffset = sni.addrOffset, addrLen = sni.addrLen;
      const addrBytes = chunk.subarray(addrOffset, addrOffset + addrLen);
      return result.handshake = new Uint8Array([chunk[0], 0]), result.success = !0, result.parsedRequest = {addrType: addrType, addrBytes: addrBytes, host: binaryAddrToString(addrType, addrBytes), dataOffset: dataOffset, port: port, isAiDomain: sni.isAiDomain}, 
      result;
    }
  }
  return len < 22 ? (result.needMore = !0, result) : result;
}, txtdnsResult = async txtdns => {
  const answer = await (async (hostname, recordType) => {
    const q = "?name=" + hostname + "&type=" + recordType;
    try {
      const res = await fetch("https://cloudflare-dns.com/dns-query" + q, dohJsonHeaders);
      if (!res.ok) return null;
      const data = await res.json();
      return data?.Answer || data?.answer || null;
    } catch {return null;}
  })(txtdns, "TXT");
  if (!answer) return null;
  let txtData, i = 0, len = answer.length;
  for (;i < len; i++) if (16 === answer[i].type) {
    txtData = answer[i].data;
    break;
  }
  if (!txtData) return null;
  34 === txtData.charCodeAt(0) && 34 === txtData.charCodeAt(txtData.length - 1) && (txtData = txtData.slice(1, -1));
  const raw = txtData.split(/,|\\010|\n/), prefixes = [];
  for (i = 0, len = raw.length; i < len; i++) {
    const s = raw[i].trim();
    s && prefixes.push(s);
  }
  return prefixes.length ? prefixes : null;
}, proxyIpRegex = /william|fxpip/i, txtCache = new Map, connectProxyIp = async (param, txt) => {
  if (txt || proxyIpRegex.test(param)) {
    const resolvedIps = await (async param => {
      const now = Date.now(), cached = txtCache.get(param);
      if (cached) return now - cached.t >= 3e5 && !cached.p && (cached.p = !0, txtdnsResult(param).then(ips => {ips?.length && (cached.d = ips, cached.t = Date.now());}).catch(() => {}).finally(() => {cached.p = !1;})), cached.d;
      const ips = await txtdnsResult(param);
      return ips?.length && txtCache.set(param, {d: ips, t: now, p: !1}), ips;
    })(param);
    if (!resolvedIps || 0 === resolvedIps.length) return null;
    const [host, port] = parseHostPort(resolvedIps[Math.random() * resolvedIps.length | 0], 443);
    return createConnect(host, port);
  }
  const [host, port] = parseHostPort(param, 443);
  return createConnect(host, port);
}, strategyExecutorMap = new Map([[0, (req, _param) => createConnect(req.host, req.port)], [3, async (_req, param, txt) => connectProxyIp(param, txt)]]), paramRegex = new RegExp(String.fromCharCode(40, 84, 120, 84, 73, 80, 124, 105, 112, 41, 40, 63, 58, 61, 124, 58, 92, 47, 92, 47, 124, 37, 51, 65, 37, 50, 70, 37, 50, 70, 41, 40, 91, 94, 38, 93, 43, 41, 124, 40, 80, 114, 111, 120, 89, 65, 76, 108, 124, 103, 108, 79, 66, 65, 108, 112, 114, 111, 88, 121, 124, 71, 76, 79, 98, 65, 108, 41), "gi"), directFailTable = new Set, createBufferedTcpWriter = (tcpWriter, close) => {
  const buffer = new Uint8Array(32768);
  let offset = 0, timerId = null, closed = !1;
  const flush = () => {
    if (timerId && (clearTimeout(timerId), timerId = null), !offset || closed) return;
    const len = offset;
    offset = 0;
    try {tcpWriter.write(buffer.subarray(0, len));} catch {closed || (closed = !0, timerId && (clearTimeout(timerId), timerId = null), close?.());}
  };
  return chunk => {
    if (closed) return;
    const data = chunk.constructor === Uint8Array ? chunk : new Uint8Array(chunk), len = data.byteLength;
    len && (offset + len > 32768 && flush(), buffer.set(data, offset), offset += len, 
    32768 === offset ? flush() : timerId ||= setTimeout(flush, 1));
  };
}, handleSession = async (chunk, state, request, writable, close) => {
  state.allowNeedMore && (state.needMore = !1);
  const parsed = parseProtocolChunk(chunk);
  if (parsed.handshake && await writable.send(parsed.handshake), state.allowNeedMore && parsed.needMore) return state.needMore = !0;
  if (!parsed.success) return close();
  const parsedRequest = parsed.parsedRequest, payload = chunk.subarray(parsedRequest.dataOffset), tcpResult = await (async (parsedRequest, request) => {
    let u = request.url, clean = u.slice(u.indexOf("/", 10) + 1), l = clean.length, list = [];
    const colo = request.cf?.colo, coloProxyHost = colo + "." + proxyHost;
    if (l > 3 && 47 === clean.charCodeAt(l - 4) && 84 === clean.charCodeAt(l - 3) && 117 === clean.charCodeAt(l - 2) && 110 === clean.charCodeAt(l - 1)) clean = clean.slice(0, l - 4); else {
      const c = clean.charCodeAt(l - 1);
      47 !== c && 61 !== c || (clean = clean.slice(0, l - 1));
    }
    let normalList = [], aiList = null;
    if (clean.length < 6) normalList.push({type: 0}, {type: 3, param: coloProxyHost}, {type: 3, param: proxyHost}), 
    aiList = [{type: 3, param: aiProxyip}, {type: 3, param: coloProxyHost}, {type: 3, param: proxyHost}]; else {
      const p = Object.create(null);
      let m;
      for (paramRegex.lastIndex = 0; m = paramRegex.exec(clean); ) p[(m[1] || m[3]).toLowerCase()] = !m[2] || (61 === m[2].charCodeAt(m[2].length - 1) ? m[2].slice(0, -1) : m[2]);
      const proxyItems = [], add = (targetList, v, t, txt) => {
        if (!v) return;
        const parts = decodeURIComponent(v).split(",").filter(Boolean);
        if (txt) for (let i = 0; i < parts.length; i++) targetList.push({type: t, param: parts[i], txt: txt}); else if (parts.length) {
          const parsedParams = parts.map(part => part);
          for (const p of parsedParams) targetList.push({type: t, param: p});
        }
      };
      p.proxyall || p.globalproxy || p.global ? (normalList.push(...proxyItems), normalList.length || normalList.push({type: 0}), 
      aiList = null) : (normalList.push({type: 0}, ...proxyItems), add(normalList, p.ip, 3), 
      add(normalList, p.txtip, 3, !0), normalList.push({type: 3, param: coloProxyHost}, {type: 3, param: proxyHost}), 
      aiList = [...proxyItems], add(aiList, p.ip || aiProxyip, 3), add(aiList, p.txtip, 3, !0), 
      aiList.push({type: 3, param: coloProxyHost}, {type: 3, param: proxyHost}));
    }
    list = normalList, aiList && parsedRequest.isAiDomain && "HKG" === colo && (list = aiList);
    const skipDirect = list.length > 1 && (parsedRequest.isAiDomain || directFailTable.has(parsedRequest.host));
    for (const {type: type, param: param, txt: txt} of list) if (0 !== type || !skipDirect) {
      try {
        const exec = strategyExecutorMap.get(type), socket = await (exec?.(parsedRequest, param, txt));
        if (socket) return {socket: socket};
      } catch {}
      0 === type && (directFailTable.add(parsedRequest.host), directFailTable.size > 200 && directFailTable.delete(directFailTable.values().next().value));
    }
    return null;
  })(parsedRequest, request);
  if (!tcpResult) return close();
  state.tcpSocket = tcpResult.socket;
  const tcpWriter = state.tcpSocket.writable.getWriter();
  state.rawTcpWriter = tcpWriter, state.tcpWriter = state.xwebPipeTo ? chunk => tcpWriter.write(chunk) : createBufferedTcpWriter(tcpWriter, close), 
  payload.byteLength && tcpWriter.write(payload), state.xwebPipeTo || (async (readable, writable, close) => {
    let done, value, bufferView = new Uint8Array(524288), spareBuffer = new ArrayBuffer(4096), offset = 0, transferred = 1048576, timerId = null, isReading = !1, needsFlush = !1, protectFlush = !1;
    const flushBuffer = () => {
      if (isReading) return needsFlush = !0;
      offset > 0 && (writable.send(bufferView.subarray(0, offset)), transferred += offset, 
      offset = 0), needsFlush = !1, protectFlush = !1, timerId && (clearTimeout(timerId), 
      timerId = null);
    }, reader = readable.getReader({mode: "byob"});
    try {
      for (;;) {
        if (transferred >= 1048576) for (transferred = 0; writable.bufferedAmount > 2097152; ) {
          if (void 0 !== writable.readyState && 1 !== writable.readyState) throw new Error("socket closed");
          await scheduler.wait(4);
        }
        if (offset > 0 && protectFlush ? (({done: done, value: value} = await reader.read(new Uint8Array(spareBuffer, 0, 4096))), 
        bufferView.set(value, offset), spareBuffer = value.buffer) : (isReading = offset > 0, 
        ({done: done, value: value} = await reader.read(new Uint8Array(bufferView.buffer, offset, 4096))), 
        isReading = !1, bufferView = new Uint8Array(value.buffer)), done) break;
        const chunkLen = value.byteLength;
        offset += chunkLen, needsFlush || offset > 520192 ? flushBuffer() : (protectFlush = chunkLen < 4096, 
        timerId ||= setTimeout(flushBuffer, 2));
      }
    } catch {offset = 0, close?.();} finally {isReading = !1, flushBuffer();}
  })(state.tcpSocket.readable, writable, close).catch(close);
}, handleWebSocketConn = async (webSocket, request) => {
  const refererHeader = request.headers.get("Referer"), protocolHeader = refererHeader || request.headers.get("sec-websocket-protocol");
  let earlyDataHeader = null;
  refererHeader ? earlyDataHeader = protocolHeader.slice(request.headers.get("host").length) : protocolHeader && (earlyDataHeader = protocolHeader);
  const earlyData = earlyDataHeader ? Uint8Array.fromBase64(earlyDataHeader, {alphabet: "base64url"}) : null, state = {tcpWriter: null, tcpSocket: null};
  let processingQueue = null;
  const close = () => {webSocket.close(1011, "WebSocket is closed");};
  processingQueue = ((consume, close) => {
    const queue = new Array(256).fill(null);
    let head = 0, tail = 0, size = 0, drainActive = !1, closed = !1;
    const closeQueue = () => {
      if (!closed) {
        closed = !0;
        for (let i = 0; i < 256; i++) queue[i] = null;
        close?.();
      }
    }, drainQueue = async () => {
      if (!closed) try {
        for (;size > 0 && !closed; ) {
          const chunk = queue[head];
          queue[head] = null, head = head + 1 & 255, size--, await consume(chunk);
        }
      } catch {closeQueue();} finally {drainActive = !1;}
    };
    return chunk => {
      if (!closed) {
        if (256 === size) return closeQueue();
        queue[tail] = chunk, tail = tail + 1 & 255, size++, drainActive || (drainActive = !0, 
        queueMicrotask(drainQueue));
      }
    };
  })(chunk => state.tcpWriter ? state.tcpWriter(chunk) : handleSession(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk), state, request, webSocket, close), close), 
  earlyData && processingQueue(earlyData), webSocket.addEventListener("message", event => (state.tcpWriter || processingQueue)(event.data)), 
  webSocket.addEventListener("error", close);
}, xwebHeaders = {"Content-Type": "application/octet-stream", "grpc-status": "0", "X-Accel-Buffering": "no", "Cache-Control": "no-store"};
export default {async fetch(request) {
  if ("POST" === request.method && request.headers.get("content-type")?.startsWith("application/grpc")) return (async request => {
    const reader = request.body?.getReader({mode: "byob"});
    if (!reader) return new Response(null, {status: 400});
    const state = {tcpWriter: null, tcpSocket: null, needMore: !1, allowNeedMore: !0, disableSsAead: !0, xwebPipeTo: !0}, bridge = new IdentityTransformStream({highWaterMark: 1048576}), upBridge = new IdentityTransformStream({highWaterMark: 1073741824}), responseWriter = bridge.writable.getWriter(), close = () => {state.xwebPipeTo && (state.xwebPipeTo = !1, reader.cancel().catch(() => {}), responseWriter.close().catch(() => {}));}, writable = {send(chunk) {if (chunk?.byteLength) return responseWriter.write(chunk);}};
    return (async () => {
      let done, value, bufferView = new Uint8Array(32768), spareBuffer = new ArrayBuffer(8192), used = 0, uploaded = 0, timerId = null;
      const flush = () => {
        used > 0 && state.tcpWriter && bufferView && (state.tcpWriter(bufferView.subarray(0, used)), 
        used = 0), timerId && (clearTimeout(timerId), timerId = null);
      };
      try {
        for (;used > 0 && state.tcpWriter ? (({done: done, value: value} = await reader.read(new Uint8Array(spareBuffer, 0, 8192))), 
        bufferView.set(value, used), spareBuffer = value.buffer) : (({done: done, value: value} = await reader.read(new Uint8Array(bufferView.buffer, used, 8192))), 
        bufferView = new Uint8Array(value.buffer)), !done; ) {
          const chunkLen = value.byteLength;
          if (chunkLen) if (used += chunkLen, state.tcpWriter) {
            if (++uploaded >= 8e3) {
              flush(), await state.rawTcpWriter.ready, reader.releaseLock(), state.rawTcpWriter.releaseLock(), 
              state.xwebPipeTo = !1, bufferView = null, spareBuffer = null, request.body.pipeThrough(upBridge).pipeTo(state.tcpSocket.writable);
              break;
            }
            used > 24576 ? flush() : timerId ||= setTimeout(flush, 1);
          } else state.needMore = !1, await handleSession(bufferView.subarray(0, used), state, request, writable, close), 
          state.tcpSocket && state.xwebPipeTo && !state.downstreamPiped && (state.downstreamPiped = !0, 
          responseWriter.releaseLock(), state.tcpSocket.readable.pipeTo(bridge.writable)), 
          state.needMore || (used = 0);
        }
      } catch {used = 0, close();} finally {flush();}
    })().catch(close), new Response(bridge.readable, {headers: xwebHeaders});
  })(request);
  if ("websocket" === request.headers.get("Upgrade")) {
    const {0: clientSocket, 1: webSocket} = new WebSocketPair;
    return webSocket.accept(), webSocket.binaryType = "arraybuffer", handleWebSocketConn(webSocket, request), 
    new Response(null, {status: 101, webSocket: clientSocket});
  }
  return new Response(null, {status: 404});
}};
