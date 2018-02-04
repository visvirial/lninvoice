
import LNInvoice from '../src/LNInvoice';

import fixtures from './fixtures';

import mocha from 'mocha';
import chai from 'chai';
const should = chai.should();

describe('Decode', () => {
	for(let idx in fixtures.invoices) {
		let invoice = fixtures.invoices[idx];
		describe(`test vector: [${idx}]`, () => {
			it('should have a valid signature', () => {
				LNInvoice.checkSignature(invoice.invoice, fixtures.pubkey).should.equal(true);
			});
			const inv = LNInvoice.fromBech32(invoice.invoice);
			for(let key in invoice.tests) {
				it(`should have a desired ${key}`, () => {
					switch(key) {
						// Numeric.
						case 'amount':
						case 'timestamp':
						case 'expiry':
						case 'cltv_expiry':
						// String.
						case 'prefix':
						case 'multiplier':
						case 'description':
						case 'fallback_addr':
							should.equal(inv[key], invoice.tests[key]);
							break;
						// Buffer.
						case 'payment_hash':
						case 'pubkey':
						case 'description_hash':
							should.not.equal(inv[key], null);
							should.equal((<Buffer>inv[key]).toString('hex'), invoice.tests[key]);
							break;
						case 'routing_info':
						default:
							throw new Error('Invalid fixture key!');
					}
				});
			}
		});
	}
});

