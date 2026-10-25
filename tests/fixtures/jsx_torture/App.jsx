import React from 'react';
import { identity } from './util.tsx';

// decoys, none of them a sink: eval(location.hash), el.innerHTML = x, require('child_process')
/* a block comment: eval(location.hash) and document.body.innerHTML = location.hash */
const NOTE = "eval(location.hash), el.innerHTML = x and child_process in a string";
const TEMPLATE_TEXT = `template text: eval(code); el.innerHTML = html; require('child_process')`;
const NESTED = `one ${`two ${`three ${identity(3)}`}`}`;
const PATH_RE = /^\/api\/v1\/'?[a-z]+\//;
const holder = { eval: (value) => value, innerHTML: 'x', child_process: 'y' };
const echoed = holder.eval(NESTED);

export function App({ items }) {
  const count = items.length;
  return (
    <div className="app">
      <h1>Don't panic</h1>
      <p>it's fine</p>
      <Icon name="x" />{count}
      <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul>
      <p>{NOTE}</p><p>{TEMPLATE_TEXT}</p><p>{PATH_RE.test(echoed) ? 'match' : 'no match'}</p>
      <p>a</p>{eval(location.hash)}<p>b</p>
      <p>Don't</p>{eval(location.hash)}
      <a href="https://example.org">https://example.org</a>{eval(location.hash)}
      <p>Don't</p>{eval(location.hash)}<p>didn't</p>
    </div>
  );
}
