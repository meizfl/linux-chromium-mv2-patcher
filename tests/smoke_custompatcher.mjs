// Optional real-browser check; Node 22+ with built-in WebSocket, no dependencies.
// node tests/smoke_custompatcher.mjs /path/to/helium [original|patched] [--sync-url] [--gaia-url]
// The GAIA check validates native URL construction, not successful account login.
// Uses only a disposable profile and a fictional password; never a user profile.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

const [input, expected = 'patched'] = process.argv.slice(2);
const checkSyncUrl = process.argv.slice(2).includes('--sync-url');
const checkGaiaUrl = process.argv.slice(2).includes('--gaia-url');
assert(input && ['original', 'patched'].includes(expected),
  'Usage: node tests/smoke_custompatcher.mjs BINARY [original|patched]');
const binary = resolve(input);
const patched = expected === 'patched';
const profile = await mkdtemp(`${tmpdir()}/helium-custompatcher-smoke-`);
const username = 'custompatcher-disposable-test';
let browser;

async function launch() {
  const child = spawn(binary, ['--headless', '--no-first-run',
    '--no-default-browser-check', `--user-data-dir=${profile}`,
    '--remote-debugging-port=0', 'about:blank'], {
    stdio: ['ignore', 'ignore', 'pipe'],
    env: {...process.env, XDG_CONFIG_HOME: profile},
  });
  let stderr = '';
  let spawnError;
  child.on('error', error => { spawnError = error; });
  const exited = new Promise(r => child.once('close', r));
  child.stderr.on('data', data => { stderr += data; });
  const pending = new Map();
  let ws;
  let counter = 0;
  const result = {
    child, exited, exceptions: [],
    async close() {
      if (ws?.readyState === WebSocket.OPEN) {
        try { await result.call('Browser.close'); } catch { /* process may have exited */ }
        ws.close();
      }
      if (child.exitCode === null && child.signalCode === null) {
        const timeout = setTimeout(() => child.kill('SIGKILL'), 5000);
        try { await exited; } finally { clearTimeout(timeout); }
      }
    },
    call(method, params = {}, sessionId) {
      const id = ++counter;
      return new Promise((fulfill, reject) => {
        const timeout = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`CDP timeout: ${method}`));
        }, 10000);
        pending.set(id, {fulfill, reject, timeout});
        ws.send(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}));
      });
    },
    async page(url, ready = "document.readyState === 'complete' && !!document.querySelector('settings-ui,password-manager-app')") {
      const {targetId} = await result.call('Target.createTarget', {url: 'about:blank'});
      const {sessionId} = await result.call('Target.attachToTarget', {targetId, flatten: true});
      await result.call('Runtime.enable', {}, sessionId);
      await result.call('Page.enable', {}, sessionId);
      await result.call('Page.navigate', {url}, sessionId);
      const evaluate = async expression => {
        const response = await result.call('Runtime.evaluate',
          {expression, awaitPromise: true, returnByValue: true}, sessionId);
        if (response.exceptionDetails) throw new Error(JSON.stringify(response.exceptionDetails));
        return response.result.value;
      };
      for (let i = 0; i < 100; i++) {
        if (await evaluate(ready)) {
          return evaluate;
        }
        await delay(100);
      }
      throw new Error(`WebUI failed to load: ${url}`);
    },
  };
  try {
    for (let i = 0; i < 100 && !stderr.includes('DevTools listening on'); i++) {
      if (spawnError) throw spawnError;
      if (child.exitCode !== null || child.signalCode !== null) throw new Error(stderr);
      await delay(100);
    }
    const url = stderr.match(/DevTools listening on (ws:\/\/\S+)/)?.[1];
    if (!url) throw new Error(`No DevTools endpoint: ${stderr}`);
    ws = new WebSocket(url);
    await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
    ws.onmessage = ({data}) => {
      const message = JSON.parse(data);
      if (message.id) {
        const callback = pending.get(message.id);
        if (!callback) return;
        pending.delete(message.id);
        clearTimeout(callback.timeout);
        if (message.error) callback.reject(new Error(JSON.stringify(message.error)));
        else callback.fulfill(message.result);
      } else if (message.method === 'Runtime.exceptionThrown') {
        result.exceptions.push(message.params);
      }
    };
    return result;
  } catch (error) {
    ws?.close();
    child.kill('SIGKILL');
    await exited;
    throw error;
  }
}

const getPref = "new Promise(r=>chrome.settingsPrivate.getPref('credentials_enable_service',r))";
const savedTestEntry = `new Promise(r=>chrome.passwordsPrivate.getSavedPasswordList(p=>r(p.some(v=>v.username===${JSON.stringify(username)}))))`;
try {
  browser = await launch();
  let evaluate = await browser.page('chrome://settings/autofill');
  const settings = await evaluate(`(async()=>{const module=await import('chrome://settings/settings.js');
    const menu=document.querySelector('settings-ui')?.shadowRoot?.querySelector('settings-menu');
    return {route:!!module.routes.AUTOFILL,menu:!!menu?.shadowRoot?.querySelector('#autofill')};})()`);
  assert.deepEqual(settings, {route: patched, menu: patched});
  const before = await evaluate(getPref);
  assert.equal(before.enforcement === 'ENFORCED', !patched);
  const enabled = await evaluate(`new Promise(r=>chrome.settingsPrivate.setPref('credentials_enable_service',true,'',r))`);
  assert.equal(enabled, patched);
  assert.equal((await evaluate(getPref)).value, patched);
  if (patched) {
    evaluate = await browser.page('chrome://password-manager/passwords');
    const error = await evaluate(`new Promise(r=>chrome.passwordsPrivate.addPassword({
      url:'https://custompatcher.invalid/',username:${JSON.stringify(username)},
      password:'Disposable-test-only-123!',note:'',useAccountStore:false},
      ()=>r(chrome.runtime.lastError?.message??null)))`);
    assert.equal(error, null);
    assert.equal(await evaluate(savedTestEntry), true);
    assert.deepEqual(browser.exceptions, []);
    await browser.close();
    browser = await launch();
    evaluate = await browser.page('chrome://settings/autofill');
    assert.equal((await evaluate(getPref)).value, true, 'Saving preference must survive restart');
    evaluate = await browser.page('chrome://password-manager/passwords');
    assert.equal(await evaluate(savedTestEntry), true, 'Test password must survive restart');
  }
  if (checkSyncUrl) {
    const evaluate = await browser.page('chrome://sync-internals', "document.readyState === 'complete'");
    let text = '';
    for (let i = 0; i < 50; i++) {
      text = await evaluate(`(()=>{const parts=[];const walk=n=>{
        if(n.nodeType===3){const t=n.textContent.trim();if(t)parts.push(t)}
        if(n.shadowRoot)walk(n.shadowRoot);for(const c of n.childNodes??[]){
          if(c.nodeType===1&&['SCRIPT','STYLE'].includes(c.tagName))continue;walk(c)}};
        walk(document.body);return parts.join(' ')})()`);
      if (text.includes('https://clients4.google.com/chrome-sync')) break;
      await delay(100);
    }
    assert(text.includes('https://clients4.google.com/chrome-sync'), 'Real Google Sync server URL expected');
    assert(!text.includes('9oo91e.qjz9zk/chrome-sync'), 'Substituted Sync server must be absent');
    assert(!text.includes('%00'), 'URL must not contain padded NUL bytes');
  }
  if (checkGaiaUrl) {
    const evaluate = await browser.page('chrome://settings/people');
    await evaluate("chrome.send('SyncSetupStartSignIn',[0]);true");
    let signin;
    for (let i = 0; i < 50; i++) {
      const {targetInfos} = await browser.call('Target.getTargets');
      signin = targetInfos.find(t => t.url.startsWith('https://accounts.google.com/'));
      if (signin) break;
      await delay(100);
    }
    assert(signin, 'Native sign-in must navigate to accounts.google.com');
    const url = new URL(signin.url);
    assert.equal(url.searchParams.get('continue'), 'https://www.google.com/');
    assert(!signin.url.includes('qjz9zk') && !signin.url.includes('%00'), 'Clean sign-in URL expected');
  }
  assert.deepEqual(browser.exceptions, []);
  console.log(`PASS: ${expected} Helium; menu/routes, credential policy${patched ? ', local password storage and restart persistence' : ''}${checkSyncUrl ? ', restored Sync URL' : ''}${checkGaiaUrl ? ', restored native sign-in and continuation URLs' : ''}`);
} finally {
  if (browser) await browser.close();
  await rm(profile, {recursive: true, force: true});
}
