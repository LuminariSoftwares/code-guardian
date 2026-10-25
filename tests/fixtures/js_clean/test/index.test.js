'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { greet } = require('../src/index.js');

test('greet capitalises and shouts the name', () => {
  assert.strictEqual(greet('ada'), 'ADA!');
});
