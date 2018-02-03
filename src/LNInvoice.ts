/**
 * vim: set filetype=typescript:
 */

import bech32 from 'bech32';
import bitcoin from 'bitcoinjs-lib';
import BigInteger from 'bigi';

class LNInvoice {
	
	prefix: string = 'lnbc';
	amount: number = 0;
	multiplier: string = '';
	
	timestamp: number;
	signature: (Buffer|null) = null;
	
	// p(1).
	payment_hash: (string|null) = null;
	// d(13).
	description: (string|null) = null;
	// n(19).
	pubkey: (string|null) = null;
	// h(23).
	description_hash: (string|null) = null;
	// x(6).
	expiry: number = 3600;
	// c(24).
	cltv_expiry: number = 9;
	// f(9).
	fallback_addr: (string|null) = null;
	// r(3).
	routing_info: Buffer[] = [];
	
	constructor() {
		this.timestamp = Math.floor(new Date().getTime() / 1000);
	}
	
	static fromWordsToBytes(words: Buffer, trim: boolean=true): Buffer {
		const buf: number[] = [];
		for(let loc: number=0; loc<words.length*5; loc++) {
			const loc5 = Math.floor(loc / 5);
			const loc8 = loc >> 3;
			if(loc%8 === 0) buf[loc8]=0;
			buf[loc8] |= ((words[loc5] >> (4 - (loc%5))) & 1) << (7 - (loc%8));
		}
		if(trim && words.length%8 !== 0) {
			buf.pop();
		}
		return Buffer.from(buf);
	}
	
	static decodeBech32HumanReadable(hr: string): {prefix: string, amount: number, multiplier: string} {
		const match = hr.match(/^([a-zA-Z]+)(\d*)([munp]?)$/);
		if(!match) {
			throw new Error('Invalid human readable part!');
		}
		return {
			prefix: match[1],
			amount: (match[2] == '' ? -1 : +match[2]),
			multiplier: match[3],
		};
	}
	
	static checkSignature(str: string, pubkey_raw: string): boolean {
		const dec = bech32.decode(str, Number.MAX_VALUE);
		const sig_data = Buffer.concat([
			Buffer.from(dec.prefix),
			LNInvoice.fromWordsToBytes(dec.words.slice(0, dec.words.length-104), false)]);
		const sig_hash = bitcoin.crypto.sha256(sig_data);
		const signature_raw = Buffer.from(bech32.fromWords(dec.words.slice(dec.words.length-104)));
		const signature = new bitcoin.ECSignature(
			BigInteger.fromBuffer(signature_raw.slice(0, 32)),
			BigInteger.fromBuffer(signature_raw.slice(32, 64)));
		const pubkey = bitcoin.ECPair.fromPublicKeyBuffer(Buffer.from(pubkey_raw, 'hex'), bitcoin.networks.bitcoin);
		return pubkey.verify(sig_hash, signature);
	}
	
	static fromBech32(str: string): LNInvoice {
		const inv = new LNInvoice();
		const dec = bech32.decode(str, Number.MAX_VALUE);
		// Decode human-readable part of bech32.
		const hr = LNInvoice.decodeBech32HumanReadable(dec.prefix);
		inv.prefix = hr.prefix;
		inv.amount = hr.amount;
		inv.multiplier = hr.multiplier;
		// Read timestamp.
		inv.timestamp = (dec.words[0] << 30) | (dec.words[1] << 25) | (dec.words[2] << 20) |
		                (dec.words[3] << 15) | (dec.words[4] << 10) | (dec.words[5] <<  5) | dec.words[6];
		// Read signature.
		inv.signature = Buffer.from(bech32.fromWords(dec.words.slice(dec.words.length-104)));
		// Read tagged part.
		const tagged = dec.words.slice(7, dec.words.length-104);
		for(let cursor: number=0; cursor<tagged.length;) {
			const type = tagged[cursor];
			const data_length = (tagged[cursor+1] << 5) + (tagged[cursor+2]);
			const data_raw = tagged.slice(cursor+3, cursor+3+data_length);
			cursor += 3 + data_length;
			const data = LNInvoice.fromWordsToBytes(data_raw);
			switch(type) {
				// Payment hash.
				case 1:
					inv.payment_hash = data.toString('hex').slice(0, 64);
					break;
				// Short description.
				case 13:
					inv.description = data.toString();
					break;
				/*
				// Public key for payee.
				case 19:
					break;
				// SHA256 description.
				case 23:
					break;
				*/
				// expiry
				case 6:
					inv.expiry = data.readUIntBE(0, data.length);
					break;
				default:
					console.log(`Unknown type = ${type}`);
					console.log(`data = ${data_raw.join(' ')}`);
			}
		}
		return inv;
	}
	
	/*
	toBech32(): string {
	}
	*/
	
}

export = LNInvoice;

