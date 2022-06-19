# kyber.wasm

kyber.wasm is a wasm of cloudflare circl kyber.

## how to use

download compiled files or clone this repo and compile.

you must have to import `main.wasm` and `wasm_exec.js` to your app, like `index.html`.

a process in web console.

```javascript
wasm_exec.js:22 2022/06/19 22:23:23 Load Kyber.WASM
let a = newKeyPair1024()
// undefined
let b = newKeyPair1024()
//  undefined
let enc = encrypt1024(a['private'], b['public'])
// undefined
let dec = decrypt1024(b['private'], enc['ciphertext'])
/// undefined
enc['shared']
// (32) [12, 123, 225, 192, 156, 36, 134, 194, 180, 191, 215, 18, 226, 109, 253, 215, 142, 230, 135, 55, 110, 252, 155, 20, 146, 177, 240, 128, 114, 87, 174, 132]
dec['shared']
// (32) [12, 123, 225, 192, 156, 36, 134, 194, 180, 191, 215, 18, 226, 109, 253, 215, 142, 230, 135, 55, 110, 252, 155, 20, 146, 177, 240, 128, 114, 87, 174, 132]
```
