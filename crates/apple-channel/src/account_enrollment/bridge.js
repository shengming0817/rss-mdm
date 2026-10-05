'use strict';
const root = `/api/v1/identity/tenants/${document.body.dataset.tenant}`;
const login = document.querySelector('#login');
const finish = document.querySelector('#finish');
const message = document.querySelector('#message');
let session;
const switchAccount = document.createElement('button');
switchAccount.textContent = '切换 RSS 账户';
switchAccount.hidden = true;
finish.after(switchAccount);
switchAccount.addEventListener('click', async () => {
  try {
    await call('/session/logout', {});
    session = undefined;
    finish.hidden = true;
    finish.elements.csrf.value = '';
    switchAccount.hidden = true;
    login.hidden = false;
    message.textContent = '请登录与组织账户关联的 RSS 账户。';
  } catch (error) { message.textContent = error.message; }
});
async function call(path, body) {
  const headers = {'x-identity-request': '1'};
  if (body) headers['content-type'] = 'application/json';
  if (session) headers['x-csrf-token'] = session.csrfToken;
  const result = await fetch(root + path, {method: body ? 'POST' : 'GET', headers, credentials: 'same-origin', body: body ? JSON.stringify(body) : undefined});
  if (!result.ok) throw new Error('认证未完成，请重新登录或联系管理员检查账户绑定。');
  return result.status === 204 ? undefined : result.json();
}
function ready(value) {
  session = value;
  finish.elements.csrf.value = value.csrfToken;
  finish.hidden = false;
  login.hidden = true;
  switchAccount.hidden = false;
  message.textContent = 'RSS 会话已登录。继续时将核对组织账户绑定；账户不匹配时请切换 RSS 账户。';
}
login.addEventListener('submit', async event => {
  event.preventDefault();
  try { ready(await call('/login', {login: login.elements.login.value, password: login.elements.password.value})); }
  catch (error) { message.textContent = error.message; }
  finally { login.elements.password.value = ''; }
});
(async () => {
  try { ready(await call('/session')); } catch (_) { /* Display the existing Identity login options. */ }
  try {
    const options = await call('/login-options');
    for (const provider of options.providers) {
      const button = document.createElement('button');
      button.textContent = provider.label || '使用组织身份登录';
      button.addEventListener('click', async () => {
        try {
          const result = await call(`/oidc/${provider.providerId}/login`, {returnTarget: 'apple-account-enrollment'});
          window.location.assign(result.authorizationUrl);
        } catch (error) { message.textContent = error.message; }
      });
      document.querySelector('#providers').appendChild(button);
    }
  } catch (_) { /* Local-only deployments have no federated login options. */ }
})();
