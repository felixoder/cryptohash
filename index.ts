class SHA256 {
  private static readonly K: number[] = [
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

  private static readonly H: number[] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ];

  private static padMessage(message: Uint8Array): Uint8Array {
    const length = message.length;
    const bitLength = length * 8;
    const paddingLength = (512 + 448 - (bitLength + 1) % 512) % 512;
    const paddedLength = length + Math.ceil(paddingLength / 8) + 8;
    
    const paddedMessage = new Uint8Array(paddedLength);
    paddedMessage.set(message);
    paddedMessage[length] = 0x80;
    
    const view = new DataView(paddedMessage.buffer);
    view.setBigUint64(paddedLength - 8, BigInt(bitLength), false);
    
    return paddedMessage;
  }

  private static rotr(x: number, n: number): number {
    return (x >>> n) | (x << (32 - n));
  }

  private static compressBlock(block: Uint32Array, hash: Uint32Array): void {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      w[i] = (block[i] & 0xff) << 24 | (block[i] & 0xff00) << 8 | 
             (block[i] & 0xff0000) >> 8 | (block[i] & 0xff000000) >> 24;
    }

    for (let i = 16; i < 64; i++) {
      const s0 = SHA256.rotr(w[i - 15], 7) ^ SHA256.rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = SHA256.rotr(w[i - 2], 17) ^ SHA256.rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }

    let a = hash[0], b = hash[1], c = hash[2], d = hash[3];
    let e = hash[4], f = hash[5], g = hash[6], h = hash[7];


    for (let i = 0; i < 64; i++) {
      const S1 = SHA256.rotr(e, 6) ^ SHA256.rotr(e, 11) ^ SHA256.rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256.K[i] + w[i]) | 0;
      const S0 = SHA256.rotr(a, 2) ^ SHA256.rotr(a, 13) ^ SHA256.rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

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
  }

  private static toBytes(input: string): Uint8Array {
    const bytes = new TextEncoder().encode(input);
    return bytes;
  }

  private static toHex(hash: Uint32Array): string {
    return Array.from(hash).map(x => x.toString(16).padStart(8, '0')).join('');
  }

  public static hash(input: string): string {
    const message = SHA256.toBytes(input);
    const paddedMessage = SHA256.padMessage(message);
    const hash = new Uint32Array(SHA256.H);

    for (let i = 0; i < paddedMessage.length; i += 64) {
      const block = new Uint32Array(paddedMessage.buffer, i, 16);
      SHA256.compressBlock(block, hash);
    }

    return SHA256.toHex(hash);
  }
}

// Export the SHA256 class
export { SHA256 };


// Implementation of Keccak256
