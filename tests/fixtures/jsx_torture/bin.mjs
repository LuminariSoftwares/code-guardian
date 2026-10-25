#!/usr/bin/env node
// hashbang above; eval(location.hash) in this comment is not a sink
import { identity } from './util.tsx';

const big = 10n;
const maybe = identity(globalThis.config)?.name ?? 'torture';
console.log(maybe, big);
