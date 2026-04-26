// 前端脚本：自动隐藏 flash、签收确认、写信字数计数、收件人自动补全、按需密码流
document.addEventListener('DOMContentLoaded', function () {
  // 自动隐藏 flash 提示
  const flashes = document.querySelectorAll('.flash');
  if (flashes.length) {
    setTimeout(() => {
      flashes.forEach(f => {
        f.style.transition = 'opacity 0.6s ease';
        f.style.opacity = '0';
        setTimeout(() => { if (f.parentNode) f.parentNode.removeChild(f); }, 700);
      });
    }, 5000);
  }

  // 侧边栏切换（移动端）
  try {
    const toggleBtn = document.getElementById('toggle-sidebar');
    const sidebar = document.querySelector('.sidebar');
    if (toggleBtn && sidebar) {
      toggleBtn.addEventListener('click', function () {
        sidebar.classList.toggle('open');
      });
    }
  } catch (e) {}

  // 自动补全（compose）
  const recipientInput = document.getElementById('recipient_email');
  const suggBox = document.getElementById('recipient-suggestions');
  if (recipientInput && suggBox) {
    let debounceTimer = null;
    recipientInput.addEventListener('input', function () {
      const q = this.value.trim();
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        if (!q) { suggBox.style.display = 'none'; return; }
        fetch(`/api/users/search?q=${encodeURIComponent(q)}`)
          .then(r => r.json())
          .then(data => {
            suggBox.innerHTML = '';
            if (!data || data.length === 0) { suggBox.style.display = 'none'; return; }
            data.forEach(it => {
              const div = document.createElement('div');
              div.className = 'autocomplete-item';
              div.innerHTML = `<strong>${it.username}</strong> &nbsp; <span style="color:#666">${it.email}</span>`;
              div.addEventListener('click', () => {
                recipientInput.value = it.email;
                suggBox.style.display = 'none';
              });
              suggBox.appendChild(div);
            });
            suggBox.style.display = 'block';
          }).catch(()=>{ suggBox.style.display = 'none'; });
      }, 250);
    });
    document.addEventListener('click', (e) => {
      if (!suggBox.contains(e.target) && e.target !== recipientInput) suggBox.style.display = 'none';
    });
  }

  // Compose: AJAX submit with "need_password" flow
  const composeForm = document.getElementById('compose-form');
  if (composeForm) {
    composeForm.addEventListener('submit', function (e) {
      e.preventDefault();
      submitCompose(null);
    });

    function submitCompose(op_password) {
      const formData = new FormData(composeForm);
      if (op_password) formData.append('op_password', op_password);

      fetch(composeForm.action, {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      }).then(resp => resp.json().then(data => ({status: resp.status, body: data})))
        .then(obj => {
          const status = obj.status;
          const data = obj.body;
          if (status === 200 && data.ok) {
            if (data.redirect) window.location = data.redirect;
            else window.location.reload();
            return;
          }
          if (status === 403 && data.need_password) {
            // 请求输入密码
            const pwd = window.prompt(data.message || '请在此输入你的登录密码以临时解密私钥：');
            if (pwd) submitCompose(pwd);
            return;
          }
          // 其它错误
          alert(data.error || '发送失败');
        }).catch(err => {
          console.error(err);
          alert('网络错误或服务器返回非 JSON');
        });
    }
  }

  // Mail view: 解密按钮（如果页面呈现了密码输入控件）
  const decryptBtn = document.getElementById('decrypt-btn');
  if (decryptBtn) {
    decryptBtn.addEventListener('click', function () {
      const pwdInput = document.getElementById('decrypt-password');
      const pwd = pwdInput ? pwdInput.value : null;
      const mailIdMatch = window.location.pathname.match(/\/mail\/(\d+)/);
      if (!mailIdMatch) return alert('无法识别邮件 ID');
      const mailId = mailIdMatch[1];
      if (!pwd) return alert('请输入密码');

      const fd = new FormData();
      fd.append('op_password', pwd);

      fetch(`/mail/${mailId}/decrypt`, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' }})
        .then(resp => resp.json())
        .then(data => {
          if (data.ok) {
            // 替换页面中的 mail 内容块
            const area = document.getElementById('mail-content-area');
            if (area) {
              let html = `<div class="mail-box">${escapeHtml(data.plaintext || '')}</div>`;
              if (data.receipts) {
                // optional
              }
              area.innerHTML = html;
            }
          } else {
            document.getElementById('decrypt-errors').textContent = data.error || '解密失败';
          }
        }).catch(err => {
          console.error(err);
          document.getElementById('decrypt-errors').textContent = '网络错误';
        });
    });
  }

  // Ack form: intercept and do same need_password flow
  const ackForm = document.getElementById('ack-form');
  if (ackForm) {
    ackForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const fd = new FormData();
      // send without password first
      fetch(ackForm.action, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' }})
        .then(resp => resp.json().then(data => ({status: resp.status, body: data})))
        .then(obj => {
          const status = obj.status;
          const data = obj.body;
          if (status === 200 && data.ok) {
            // 刷新页面以显示签收状态
            window.location.reload();
            return;
          }
          if (status === 403 && data.need_password) {
            const pwd = window.prompt(data.message || '请在此输入你的登录密码以临时解密私钥并签收：');
            if (!pwd) return;
            const fd2 = new FormData();
            fd2.append('op_password', pwd);
            fetch(ackForm.action, { method: 'POST', body: fd2, headers: { 'X-Requested-With': 'XMLHttpRequest' }})
              .then(resp2 => resp2.json())
              .then(d2 => {
                if (d2.ok) window.location.reload();
                else alert(d2.error || '签收失败');
              }).catch(()=>alert('网络错误'));
          } else {
            alert(data.error || '签收失败');
          }
        }).catch(()=>alert('网络错误'));
    });
  }

  // 小工具
  function escapeHtml(s) {
    if (!s) return '';
    return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }
});