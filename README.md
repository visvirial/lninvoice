lninvoice
=========

A tiny TypeScript (Node.js / JavaScript) library to decode or encode [Lightning Network](http://lightning.network/) invoice string (starting from 'lnbc1...' for Bitcoin mainnet).



Installation
------------

Run the following command to compile TypeScript code into JavaScript.

```
$ npm install
$ npm run build
```



Sample Code
-----------

Copy&paste the following code into `test.js` and run `node test.js` in your console.

```
const LNInvoice = require('./dist/src/LNInvoice');

//const privkey = 'e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734';
const pubkey = '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad';

const str = 'lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w';

const inv = LNInvoice.fromBech32(str);
console.log(inv);
console.log('Signature Validity:', LNInvoice.checkSignature(str, pubkey));
```


