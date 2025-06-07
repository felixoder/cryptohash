import { SHA256, MD5, Djb2 } from "./index.js";

const str = "debayan";

console.log(SHA256.hash(str));
console.log(MD5.hash(str));
console.log(Djb2.hash(str));
