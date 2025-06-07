"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Djb2 = exports.MD5 = exports.SHA256 = void 0;
var SHA256 = /** @class */ (function () {
    function SHA256() {
    }
    SHA256.padMessage = function (message) {
        var length = message.length;
        var bitLength = length * 8;
        var paddingLength = (512 + 448 - (bitLength + 1) % 512) % 512;
        var paddedLength = length + Math.ceil(paddingLength / 8) + 8;
        var paddedMessage = new Uint8Array(paddedLength);
        paddedMessage.set(message);
        paddedMessage[length] = 0x80;
        var view = new DataView(paddedMessage.buffer);
        view.setBigUint64(paddedLength - 8, BigInt(bitLength), false);
        return paddedMessage;
    };
    SHA256.rotr = function (x, n) {
        return (x >>> n) | (x << (32 - n));
    };
    SHA256.compressBlock = function (block, hash) {
        var w = new Uint32Array(64);
        for (var i = 0; i < 16; i++) {
            w[i] = (block[i] & 0xff) << 24 | (block[i] & 0xff00) << 8 |
                (block[i] & 0xff0000) >> 8 | (block[i] & 0xff000000) >> 24;
        }
        for (var i = 16; i < 64; i++) {
            var s0 = SHA256.rotr(w[i - 15], 7) ^ SHA256.rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            var s1 = SHA256.rotr(w[i - 2], 17) ^ SHA256.rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        }
        var a = hash[0], b = hash[1], c = hash[2], d = hash[3];
        var e = hash[4], f = hash[5], g = hash[6], h = hash[7];
        for (var i = 0; i < 64; i++) {
            var S1 = SHA256.rotr(e, 6) ^ SHA256.rotr(e, 11) ^ SHA256.rotr(e, 25);
            var ch = (e & f) ^ (~e & g);
            var temp1 = (h + S1 + ch + SHA256.K[i] + w[i]) | 0;
            var S0 = SHA256.rotr(a, 2) ^ SHA256.rotr(a, 13) ^ SHA256.rotr(a, 22);
            var maj = (a & b) ^ (a & c) ^ (b & c);
            var temp2 = (S0 + maj) | 0;
            h = g;
            g = f;
            f = e;
            e = (d + temp1) | 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) | 0;
        }
        hash[0] = (hash[0] + a) | 0;
        hash[1] = (hash[1] + b) | 0;
        hash[2] = (hash[2] + c) | 0;
        hash[3] = (hash[3] + d) | 0;
        hash[4] = (hash[4] + e) | 0;
        hash[5] = (hash[5] + f) | 0;
        hash[6] = (hash[6] + g) | 0;
        hash[7] = (hash[7] + h) | 0;
    };
    SHA256.toBytes = function (input) {
        var bytes = new TextEncoder().encode(input);
        return bytes;
    };
    SHA256.toHex = function (hash) {
        return Array.from(hash).map(function (x) { return x.toString(16).padStart(8, '0'); }).join('');
    };
    SHA256.hash = function (input) {
        var message = SHA256.toBytes(input);
        var paddedMessage = SHA256.padMessage(message);
        var hash = new Uint32Array(SHA256.H);
        for (var i = 0; i < paddedMessage.length; i += 64) {
            var block = new Uint32Array(paddedMessage.buffer, i, 16);
            SHA256.compressBlock(block, hash);
        }
        return SHA256.toHex(hash);
    };
    SHA256.K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    SHA256.H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19,
    ];
    return SHA256;
}());
exports.SHA256 = SHA256;
// Implementation of md5 hash
var MD5 = /** @class */ (function () {
    function MD5() {
    }
    MD5.leftRotate = function (x, c) {
        return (x << c) | (x >>> (32 - c));
    };
    MD5.hash = function (str) {
        // Initialize variables:
        var a0 = 0x67452301;
        var b0 = 0xefcdab89;
        var c0 = 0x98badcfe;
        var d0 = 0x10325476;
        // Convert string to bytes:
        var msg = new TextEncoder().encode(str);
        var originalLen = msg.length;
        // Calculate new length with padding:
        var newLen = (((originalLen + 8) >>> 6) + 1) << 6;
        var padded = new Uint8Array(newLen);
        padded.set(msg);
        padded[originalLen] = 0x80; // Append '1' bit
        // Append original length in bits as 64-bit little-endian integer:
        var bitLen = originalLen * 8;
        var view = new DataView(padded.buffer);
        view.setUint32(newLen - 8, bitLen, true);
        view.setUint32(newLen - 4, 0, true); // high bits zero for input length < 2^32 bits
        // Process each 512-bit chunk:
        for (var offset = 0; offset < newLen; offset += 64) {
            var M = new Uint32Array(16);
            for (var i = 0; i < 16; i++) {
                M[i] = view.getUint32(offset + i * 4, true); // little-endian
            }
            var A = a0, B = b0, C = c0, D = d0;
            for (var i = 0; i < 64; i++) {
                var F = void 0, g = void 0;
                if (i < 16) {
                    F = (B & C) | (~B & D);
                    g = i;
                }
                else if (i < 32) {
                    F = (D & B) | (~D & C);
                    g = (5 * i + 1) % 16;
                }
                else if (i < 48) {
                    F = B ^ C ^ D;
                    g = (3 * i + 5) % 16;
                }
                else {
                    F = C ^ (B | ~D);
                    g = (7 * i) % 16;
                }
                F = (F + A + this.K[i] + M[g]) >>> 0;
                A = D;
                D = C;
                C = B;
                B = (B + this.leftRotate(F, this.s[i])) >>> 0;
            }
            a0 = (a0 + A) >>> 0;
            b0 = (b0 + B) >>> 0;
            c0 = (c0 + C) >>> 0;
            d0 = (d0 + D) >>> 0;
        }
        // Output the final hash as hex string:
        var buffer = new ArrayBuffer(16);
        var hashView = new DataView(buffer);
        hashView.setUint32(0, a0, true);
        hashView.setUint32(4, b0, true);
        hashView.setUint32(8, c0, true);
        hashView.setUint32(12, d0, true);
        var hex = "";
        var bytes = new Uint8Array(buffer);
        for (var _i = 0, bytes_1 = bytes; _i < bytes_1.length; _i++) {
            var byte = bytes_1[_i];
            hex += byte.toString(16).padStart(2, "0");
        }
        return hex;
    };
    MD5.K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ];
    MD5.s = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];
    return MD5;
}());
exports.MD5 = MD5;
// Example usage:
// console.log(MD5.hash("hello"));
// Expected output: 5d41402abc4b2a76b9719d911017c592
// implementation of DJB2 hash
var Djb2 = /** @class */ (function () {
    function Djb2() {
    }
    Djb2.hash = function (input) {
        var hash = BigInt(5381);
        for (var i = 0; i < input.length; i++) {
            var c = BigInt(input.charCodeAt(i));
            hash = (hash * BigInt(33)) + c;
        }
        return hash;
    };
    Djb2.hashHex = function (input) {
        return this.hash(input).toString(16);
    };
    return Djb2;
}());
exports.Djb2 = Djb2;
// // Test
// console.log(Djb2.hash("Hello").toString());     // should match C's 210676686969
// console.log(Djb2.hashHex("Hello"));             // hex version
