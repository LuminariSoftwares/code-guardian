import leftPad from 'left-pad';
import { helper } from './util';

export function run(): string {
  return leftPad(helper(), 10);
}
