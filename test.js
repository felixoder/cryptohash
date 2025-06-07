"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var index_js_1 = require("./index.js");
var str = "debayan";
console.log(index_js_1.SHA256.hash(str));
console.log(index_js_1.MD5.hash(str));
console.log(index_js_1.Djb2.hash(str));
