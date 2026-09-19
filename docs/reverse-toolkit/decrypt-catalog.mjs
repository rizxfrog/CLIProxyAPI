#!/usr/bin/env node
// decrypt-catalog.mjs
// Reuses the OFFICIAL qodercli/qoderclicn bundle's own WASM glue to decrypt the
// server-driven model catalog (~/.qoder/.models/<uid>/catalog-v5|v6), which is
// AES-encrypted by qoder_auth_wasm's model_cache_decrypt(data, uid).
//
// Usage:
//   cp <bundle/qoderclicn.js> ./runner.js          # the 33MB minified bundle
//   # neutralise the CLI entry so it doesn't start: replace  ctr(async()=>{  with  (async()=>{
//   cat decrypt-catalog-harness.mjs >> runner.js   # append the block below
//   QDUID=<uid> HOME=$HOME node runner.js
//
// The appended harness block (kept separate so it can be concat-ed onto any bundle copy):
//
// (async()=>{ try{
//   await BU();                                   // bundle-internal initWasm
//   const fs=await import("node:fs");
//   const uid=process.env.QDUID||"019cbe3d-a085-78b4-a718-9d80a0dfc11f";
//   const HOME=process.env.HOME||"/home/van";
//   for(const v of ["catalog-v6","catalog-v5"]){
//     try{const txt=fs.readFileSync(`${HOME}/.qoder/.models/${uid}/${v}`,"utf-8");
//        const out=d8s(txt,uid);                  // model_cache_decrypt(contents,uid)
//        process.stdout.write(out); fs.writeFileSync("/tmp/qoder_catalog_decrypted.json",out);
//        process.exit(0);}catch(e){ if(e.code!=="ENOENT"){console.error("decrypt fail:",e.message);process.exit(4);} }
//   } console.error("no catalog"); process.exit(3);
// }catch(e){console.error("err:",e&&e.message||e);process.exit(4);} })();

console.log("See header comment. This file documents the technique; the runnable harness is appended to a bundle copy per the Usage block above.");
