/// <reference types="chrome" />
import type { CheckResult } from './lib';

const params = new URLSearchParams(location.search);
const host = params.get('host') ?? '';
const url = params.get('url') ?? '';
const $ = (id: string) => document.getElementById(id)!;
$('host').textContent = host;

(async () => {
  const tab = await chrome.tabs.getCurrent();
  const tabId = tab?.id;
  const r = tabId === undefined ? null : ((await chrome.storage.session.get(`tab:${tabId}`))[`tab:${tabId}`] as CheckResult | undefined);
  const reasons = r?.reasons?.length ? r.reasons : ['This site is listed as malicious by a FootprintX threat source.'];
  $('reasons').replaceChildren(...reasons.map((x) => Object.assign(document.createElement('li'), { textContent: x })));
  const steps = r?.nextSteps ?? [];
  $('steps').replaceChildren(...steps.map((x) => Object.assign(document.createElement('li'), { textContent: x })));

  $('back').addEventListener('click', async () => {
    if (tabId !== undefined) await chrome.runtime.sendMessage({ type: 'go-back', host, tabId });
    if (history.length > 1) history.back();
    else location.replace('about:blank');
  });
  $('proceed').addEventListener('click', async () => {
    if (tabId === undefined || !/^https?:\/\//.test(url)) return;
    await chrome.runtime.sendMessage({ type: 'proceed', host, tabId, url });
  });
})();
