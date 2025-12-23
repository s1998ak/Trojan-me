import { connect } from "cloudflare:sockets";


// Only accept WebSocket upgrades on this exact path (from your trojan:// ...?path=...)
const ALLOWED_PATH = "";
/*
Minimal Trojan-over-WebSocket Worker
-----------------------------------
- No Telegram / subscription / external fetches
- Only accepts WebSocket upgrade requests

Env:
  PASSWORD (required)
  SHA224   (optional; precomputed sha224(PASSWORD))
*/

let sha224Password = "";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ---- Small, safe HTTP endpoints (non-WS) ----
    // Visiting the Worker in a browser normally does NOT start a WebSocket upgrade,
    // so you will see "Not Found" unless you hit these endpoints.
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/healthz")) {
      return new Response("OK", { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
    }

    // Optional: show a *template* config (no password) for debugging.
    // Enable by setting ADMIN_TOKEN in Worker secrets, then open:
    //   https://<worker-domain>/config?token=<ADMIN_TOKEN>
 // ---- Admin config endpoint (path-based, no query) ----
// Access via: https://<worker-domain>/<ADMIN_TOKEN>
if (request.method === "GET") {
  const admin = env.ADMIN_TOKEN || "";
  if (admin && url.pathname === `/${admin}`) {
    const allowed = (env.WS_PATH || ALLOWED_PATH);
    const host = url.host;

    const tpl =
      `trojan://<YOUR_PASSWORD>@${host}:443?security=tls&type=ws&host=${host}&sni=${host}&path=${encodeURIComponent(allowed)}#ME`;

    return new Response(tpl + "\n", {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }
}


    // ---- Path lock for WebSocket only ----
    const allowed = (env.WS_PATH || ALLOWED_PATH);
    if (url.pathname !== allowed && url.pathname !== allowed + "/") {
      return new Response("Not Found", { status: 404 });
    }

    const upgrade = (request.headers.get("Upgrade") || "").toLowerCase();
    if (upgrade !== "websocket") {
      return new Response("Not Found", { status: 404 });
    }

    const pass = env.PASSWORD || env.pswd || env.UUID || env.uuid || env.TOKEN || "";
    if (!pass && !env.SHA224 && !env.SHA224PASS) {
      return new Response("Set PASSWORD (or SHA224) in Worker variables.", {
        status: 500,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }

    sha224Password = (env.SHA224 || env.SHA224PASS || sha224(pass)).toLowerCase();
    return handleTrojanOverWS(request);
  },
};

async function handleTrojanOverWS(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  const remoteSocketWrapper = { value: null };

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const parsed = await parseTrojanHeader(chunk);
          if (parsed.hasError) throw new Error(parsed.message);

          const tcpSocket = await connectAndWrite(
            parsed.addressRemote,
            parsed.portRemote,
            parsed.rawClientData
          );
          remoteSocketWrapper.value = tcpSocket;
          remoteSocketToWS(tcpSocket, webSocket);
        },
        close() {
          safeCloseWebSocket(webSocket);
        },
        abort() {
          safeCloseWebSocket(webSocket);
        },
      })
    )
    .catch(() => {
      safeCloseWebSocket(webSocket);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function connectAndWrite(hostname, port, firstData) {
  const tcpSocket = connect({ hostname, port });
  await tcpSocket.opened;
  if (firstData && firstData.byteLength) {
    const writer = tcpSocket.writable.getWriter();
    await writer.write(firstData);
    writer.releaseLock();
  }
  return tcpSocket;
}

async function parseTrojanHeader(buffer) {
  if (buffer.byteLength < 58) {
    return { hasError: true, message: "invalid data" };
  }

  // Trojan: sha224(password) (56 bytes ASCII hex) + CRLF
  const b56 = new Uint8Array(buffer.slice(56, 57))[0];
  const b57 = new Uint8Array(buffer.slice(57, 58))[0];
  if (b56 !== 0x0d || b57 !== 0x0a) {
    return { hasError: true, message: "invalid header format (missing CR LF)" };
  }

  const recvHash = new TextDecoder().decode(buffer.slice(0, 56)).toLowerCase();
  if (recvHash !== sha224Password) {
    return { hasError: true, message: "invalid password" };
  }

  const socks5DataBuffer = buffer.slice(58);
  if (socks5DataBuffer.byteLength < 6) {
    return { hasError: true, message: "invalid SOCKS5 request data" };
  }

  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd !== 1) {
    return {
      hasError: true,
      message: "unsupported command, only TCP (CONNECT) is allowed",
    };
  }

  const atype = view.getUint8(1);
  let addressLength = 0;
  let addressIndex = 2;
  let address = "";

  switch (atype) {
    case 1:
      addressLength = 4;
      address = new Uint8Array(
        socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
      ).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(
        socks5DataBuffer.slice(addressIndex, addressIndex + 1)
      )[0];
      addressIndex += 1;
      address = new TextDecoder().decode(
        socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
      );
      break;
    case 4: {
      addressLength = 16;
      const dataView = new DataView(
        socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
      );
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      address = ipv6.join(":");
      break;
    }
    default:
      return { hasError: true, message: `invalid addressType is ${atype}` };
  }

  if (!address) {
    return { hasError: true, message: "address is empty" };
  }

  const portIndex = addressIndex + addressLength;
  const portRemote = new DataView(socks5DataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

  return {
    hasError: false,
    addressRemote: address,
    portRemote,
    // keep same behavior as your source: skip 4 bytes after port
    rawClientData: socks5DataBuffer.slice(portIndex + 4),
  };
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let canceled = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (!canceled) controller.enqueue(event.data);
      });

      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (!canceled) controller.close();
      });

      webSocketServer.addEventListener("error", (err) => {
        controller.error(err);
      });

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    cancel() {
      canceled = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function remoteSocketToWS(remoteSocket, webSocket) {
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket connection is not open");
            return;
          }
          webSocket.send(chunk);
        },
        close() {
          safeCloseWebSocket(webSocket);
        },
        abort() {
          safeCloseWebSocket(webSocket);
        },
      })
    )
    .catch(() => {
      safeCloseWebSocket(webSocket);
    });
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: undefined, error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { earlyData: undefined, error };
  }
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (_) {}
}
function sha224(输入字符串) {
    // 内部常量和函数
    const 常量K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    function utf8编码(字符串) {
        return unescape(encodeURIComponent(字符串));
    }

    function 字节转十六进制(字节数组) {
        let 十六进制 = '';
        for (let i = 0; i < 字节数组.length; i++) {
            十六进制 += ((字节数组[i] >>> 4) & 0x0F).toString(16);
            十六进制 += (字节数组[i] & 0x0F).toString(16);
        }
        return 十六进制;
    }

    function sha224核心(输入字符串) {
        // SHA-224的初始哈希值
        let 哈希值 = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ];

        // 预处理
        const 消息长度 = 输入字符串.length * 8;
        输入字符串 += String.fromCharCode(0x80);
        while ((输入字符串.length * 8) % 512 !== 448) {
            输入字符串 += String.fromCharCode(0);
        }

        // 64位消息长度
        const 消息长度高位 = Math.floor(消息长度 / 0x100000000);
        const 消息长度低位 = 消息长度 & 0xFFFFFFFF;
        输入字符串 += String.fromCharCode(
            (消息长度高位 >>> 24) & 0xFF, (消息长度高位 >>> 16) & 0xFF,
            (消息长度高位 >>> 8) & 0xFF, 消息长度高位 & 0xFF,
            (消息长度低位 >>> 24) & 0xFF, (消息长度低位 >>> 16) & 0xFF,
            (消息长度低位 >>> 8) & 0xFF, 消息长度低位 & 0xFF
        );

        const 字数组 = [];
        for (let i = 0; i < 输入字符串.length; i += 4) {
            字数组.push(
                (输入字符串.charCodeAt(i) << 24) |
                (输入字符串.charCodeAt(i + 1) << 16) |
                (输入字符串.charCodeAt(i + 2) << 8) |
                输入字符串.charCodeAt(i + 3)
            );
        }

        // 主要压缩循环
        for (let i = 0; i < 字数组.length; i += 16) {
            const w = new Array(64).fill(0);
            for (let j = 0; j < 16; j++) {
                w[j] = 字数组[i + j];
            }

            for (let j = 16; j < 64; j++) {
                const s0 = 右旋转(w[j - 15], 7) ^ 右旋转(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                const s1 = 右旋转(w[j - 2], 17) ^ 右旋转(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
            }

            let [a, b, c, d, e, f, g, h0] = 哈希值;

            for (let j = 0; j < 64; j++) {
                const S1 = 右旋转(e, 6) ^ 右旋转(e, 11) ^ 右旋转(e, 25);
                const ch = (e & f) ^ (~e & g);
                const temp1 = (h0 + S1 + ch + 常量K[j] + w[j]) >>> 0;
                const S0 = 右旋转(a, 2) ^ 右旋转(a, 13) ^ 右旋转(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const temp2 = (S0 + maj) >>> 0;

                h0 = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }

            哈希值[0] = (哈希值[0] + a) >>> 0;
            哈希值[1] = (哈希值[1] + b) >>> 0;
            哈希值[2] = (哈希值[2] + c) >>> 0;
            哈希值[3] = (哈希值[3] + d) >>> 0;
            哈希值[4] = (哈希值[4] + e) >>> 0;
            哈希值[5] = (哈希值[5] + f) >>> 0;
            哈希值[6] = (哈希值[6] + g) >>> 0;
            哈希值[7] = (哈希值[7] + h0) >>> 0;
        }

        // 截断到224位
        return 哈希值.slice(0, 7);
    }

    function 右旋转(数值, 位数) {
        return ((数值 >>> 位数) | (数值 << (32 - 位数))) >>> 0;
    }

    // 主函数逻辑
    const 编码输入 = utf8编码(输入字符串);
    const 哈希结果 = sha224核心(编码输入);

    // 转换为十六进制字符串
    return 字节转十六进制(
        哈希结果.flatMap(h => [
            (h >>> 24) & 0xFF,
            (h >>> 16) & 0xFF,
            (h >>> 8) & 0xFF,
            h & 0xFF
        ])
    );
}

