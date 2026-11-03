import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Script} from 'node:vm';
import test from 'node:test';
const read = path => readFileSync(new URL('../../'+path, import.meta.url),'utf8');
for(const page of ['index','admin','kitchen']) {
  test(`${page}: external assets compile; authored handlers use event listeners`,()=>{
    const html=read(page+'.html'), js=read(`restaurant-${page}.js`);
    assert.doesNotMatch(html, /<script\s*>|<style>|\son\w+\s*=|\sstyle\s*=/i);
    assert.match(html,new RegExp(`src="./restaurant-${page}.js"`));
    assert.match(html,new RegExp(`href="./restaurant-${page}.css"`));
    assert.match(html,/data-api-base="https:\/\/kali.pythonanywhere.com\/api"/);
    new Script(js,{filename:`restaurant-${page}.js`});
    assert.doesNotMatch(js,/\.innerHTML\s*=|insertAdjacentHTML|\beval\s*\(|new Function\s*\(/);
    for(const match of html.matchAll(/data-action-(\w+)="(a\d+)"/g)) assert.ok(js.includes(`[data-action-${match[1]}="${match[2]}"]`));
  });
  test(`${page}: opt-in Pages migration gateway has one fixed destination and no executable code`,()=>{
    const html=read(`deploy/pages-gateway/${page==='index'?'index':page}.html`);
    assert.ok(html.includes(`content="0;url=https://kali.pythonanywhere.com/${page}.html"`));
    assert.ok(html.includes(`href="https://kali.pythonanywhere.com/${page}.html"`));
    assert.doesNotMatch(html,/<script|\son\w+=|document\.|location\./i);
    assert.match(html,/default-src 'none'/);
  });
}
