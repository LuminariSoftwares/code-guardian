'use strict';

const _ = require('lodash');
const { shout } = require('./util.js');

function greet(name) {
  return shout(_.capitalize(name));
}

module.exports = { greet };
