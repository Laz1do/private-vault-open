import { createVaultClient } from '../core/vault.js';

const $ = (id) => document.getElementById(id);
const shell = $('app-shell');
const detail = $('detail-panel');
const list = $('record-list');
const layer = $('modal-layer');
const modalCard = $('modal-card');
const search = $('search-input');
const host = window.VaultHost;
let client = null;
let snapshot = { records: [], status: 'local', lastSync: null, configured: false, pending: false, mode: 'file', needsImport: false, serverEndpoint: null };
let selectedId = null;
let query = '';
let filter = 'all';
let modalStack = [];
let modalReturnFocus = null;
let toastTimer = null;
let unsubscribe = null;
let booting = false;
let fatal = false;
let fileBusy = false;
let settingsOpening = false;
const collator = new Intl.Collator('zh-CN', { numeric: true, sensitivity: 'base' });

const icons = {
  plus: ['M12 5v14M5 12h14'],
  copy: ['M9 8V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-3', 'M5 8h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2Z'],
  edit: ['m15 4 5 5M4 20l4-1 12-12a2.1 2.1 0 0 0-3-3L5 16l-1 4Z'],
  trash: ['M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6'],
  back: ['m15 5-7 7 7 7'],
  close: ['m6 6 12 12M6 18 18 6'],
  external: ['M14 3h7v7M21 3 11 13', 'M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5'],
  lock: ['M5 10h14v11H5Z', 'M8 10V7a4 4 0 0 1 8 0v3M12 14v3'],
  note: ['M5 3h14v18H5Z', 'M9 8h6M9 12h6M9 16h4'],
  warning: ['m12 3 10 18H2L12 3Z', 'M12 9v5M12 17h.01'],
  key: ['M10.5 14.5 3 22M6 19l-2-2M9 16l-2-2', 'M21 8a5 5 0 1 1-10 0 5 5 0 0 1 10 0Z'],
  search: ['M16 16l5 5', 'M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z'],
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function icon(name, size = 18) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  for (const [key, value] of Object.entries({ viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(key, String(value));
  for (const d of icons[name] || []) {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

function button(label, className, action, iconName, testId) {
  const node = el('button', `button ${className}`);
  node.type = 'button';
  if (iconName) node.append(icon(iconName));
  node.append(el('span', '', label));
  if (testId) node.dataset.testid = testId;
  node.addEventListener('click', action);
  return node;
}

function toast(message, tone = 'success') {
  const node = $('toast');
  clearTimeout(toastTimer);
  node.textContent = message;
  node.dataset.tone = tone;
  node.hidden = false;
  toastTimer = setTimeout(() => { node.hidden = true; }, tone === 'error' ? 6000 : 3200);
}

function errorText(error) {
  const messages = {
    invalid_entry: '请检查记录名称和各项内容的长度。',
    conflict_requires_resolution: '这条记录有多个版本，请先选择要保留的版本。',
    record_not_found: '这条记录已经在其他设备上删除。',
    stale_record: '这条记录已更新。你的输入仍在这里，请先关闭编辑并查看最新版本。',
    persistence_failed: '未能保存到设备。请检查存储空间，保持应用打开并重试同步。',
    vault_too_large: '密码库已达到容量限制，请精简备注后重试。',
    invalid_vault: '密码库文件无法读取，请检查本地文件。',
    invalid_envelope: '密码库文件无法读取，请检查本地文件。',
    decrypt_failed: '无法解密密码库，请使用与你的密码库配套的专属安装包。',
    invalid_config: '应用配置不完整，请使用你保存的专属安装包。',
    invalid_file: '文件格式无效，请选择由本软件导出的密码库文件。',
    different_vault: '此设备已有其他密码库的记录，无法导入不同的密码库。',
    different_key: '这个文件的密钥与当前密码库不一致，原数据已保留。',
    needs_import: '请先导入文件，恢复现有密码库。',
    server_not_configured: '请先填写服务器地址和同步凭据。',
  };
  return messages[error?.code] || '操作未完成，请稍后重试。';
}

function versionStamp(record) {
  return record?.versions.map((v) => v.id).sort().join('|') || '';
}

function recordTitle(record) {
  return record.entry?.title || record.versions.find((v) => v.entry)?.entry.title || '待处理的记录';
}

function avatarText(title) {
  return [...String(title).trim()][0]?.toUpperCase() || '密';
}

function formatTime(value, dateOnly = false) {
  if (!value) return '';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '';
  return new Intl.DateTimeFormat('zh-CN', dateOnly ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' } : { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(date);
}

function shortLastSync(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '';
  const now = new Date();
  const sameDay = date.toDateString() === now.toDateString();
  return `最近同步 ${sameDay ? new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit' }).format(date) : formatTime(date, true)}`;
}

function visibleRecords() {
  const needle = query.trim().toLocaleLowerCase();
  return snapshot.records.filter((record) => {
    if (filter === 'conflict' && !record.conflict) return false;
    if (!needle) return true;
    return record.versions.some((version) => version.entry && ['title', 'username', 'url', 'notes'].some((field) => version.entry[field].toLocaleLowerCase().includes(needle)));
  }).sort((a, b) => collator.compare(recordTitle(a), recordTitle(b)));
}

function renderStatus() {
  const { status, configured, pending, lastSync, mode, needsImport } = snapshot;
  const state = $('sync-state');
  const labels = { local: pending ? '等待同步' : '仅保存在本地', syncing: '正在同步', synced: '已同步', offline: pending ? '离线 · 待同步' : '离线可用', error: '同步未完成' };
  state.dataset.status = status === 'error' || configured ? status : 'local';
  $('sync-label').textContent = fatal ? '无法打开' : booting ? '正在打开' : needsImport ? '等待导入恢复' : status === 'error' && !configured ? '保存未完成' : mode === 'file' ? '文件模式 · 本地保存' : configured ? (labels[status] || '等待同步') : '服务器尚未设置';
  $('sync-time').textContent = mode === 'server' && lastSync ? shortLastSync(lastSync) : configured && pending && status !== 'error' ? '修改已保存在本地' : '';
  $('sync-button').hidden = needsImport || (mode === 'file' && status !== 'error');
  $('sync-button').disabled = !client || needsImport || (!configured && status !== 'error') || status === 'syncing';
  $('sync-button').querySelector('span').textContent = !configured && status === 'error' ? '重试保存' : '同步';
  $('sync-button').setAttribute('aria-label', !configured && status === 'error' ? '重试保存到此设备' : '立即同步');
  $('add-button').disabled = !client || needsImport;
  $('mode-file').disabled = !client || needsImport || fileBusy;
  $('mode-server').disabled = !client || needsImport || fileBusy;
  $('mode-file').classList.toggle('is-active', mode === 'file');
  $('mode-file').setAttribute('aria-pressed', String(mode === 'file'));
  $('mode-server').classList.toggle('is-active', mode === 'server');
  $('mode-server').setAttribute('aria-pressed', String(mode === 'server'));
  $('import-button').disabled = !client || fileBusy;
  $('export-button').disabled = !client || needsImport || fileBusy;
  $('settings-button').disabled = !client || needsImport || fileBusy;
  const note = $('connection-note');
  const message = fatal ? !host ? '请从已安装的私人密码库应用打开。' : '无法读取密码库，请检查本地文件，原数据不会被自动清空。' : !client ? '' : needsImport ? '发现旧版密码库。请导入含原密钥的密码库文件恢复，原文件会保留。' : status === 'error' ? (snapshot.message || '操作未完成，请稍后重试。') : mode === 'file' ? '' : !configured ? '服务器尚未设置。你仍可在此设备查看和编辑密码。' : status === 'offline' ? pending ? '暂时无法连接，修改已保存在本地。下次联网打开时会自动同步。' : '暂时无法连接，仍可查看和编辑本地密码。' : '';
  note.textContent = message;
  note.hidden = !message;
  note.dataset.tone = status === 'error' || fatal ? 'error' : 'neutral';
}

function renderList() {
  const focusId = document.activeElement?.dataset.recordId;
  const scrollTop = list.scrollTop;
  $('record-count').textContent = String(snapshot.records.length);
  $('conflict-count').textContent = String(snapshot.records.filter((record) => record.conflict).length);
  $('filter-all').classList.toggle('is-active', filter === 'all');
  $('filter-all').setAttribute('aria-pressed', String(filter === 'all'));
  $('filter-conflict').classList.toggle('is-active', filter === 'conflict');
  $('filter-conflict').setAttribute('aria-pressed', String(filter === 'conflict'));
  const records = visibleRecords();
  const children = records.map((record) => {
    const row = el('button', `record-row${record.id === selectedId ? ' is-selected' : ''}`);
    row.type = 'button';
    row.dataset.recordId = record.id;
    row.dataset.testid = 'record-row';
    row.setAttribute('aria-label', `${recordTitle(record)}${record.conflict ? '，有待处理的冲突' : ''}`);
    row.setAttribute('aria-pressed', String(record.id === selectedId));
    const content = el('span', 'record-row-content');
    content.append(el('span', 'record-row-title', recordTitle(record)), el('span', 'record-row-account', record.entry?.username || record.entry?.url || (record.conflict ? '请选择要保留的版本' : '未填写账号')));
    row.append(el('span', 'record-avatar', avatarText(recordTitle(record))), content);
    if (record.conflict) row.append(el('span', 'conflict-mini'));
    if (record.conflict) row.lastChild.append(icon('warning', 16));
    row.addEventListener('click', () => selectRecord(record.id));
    return row;
  });
  if (!children.length) {
    const empty = el('div', 'list-empty');
    empty.append(el('strong', '', !client ? booting ? '正在打开密码库…' : '密码库暂不可用' : snapshot.needsImport ? '需要导入文件恢复' : query ? '没有找到相关记录' : filter === 'conflict' ? '没有待处理的冲突' : '还没有密码记录'), el('span', '', !client ? '请稍候或检查应用配置' : snapshot.needsImport ? '旧版密码库已保留，不会创建新库覆盖' : query ? '试试另一个名称、账号或网址' : filter === 'conflict' ? '所有记录都保持一致' : '点击“新增”，或导入已有密码库文件'));
    if (fatal) empty.append(button('重新打开', 'secondary list-retry', initialize, undefined, 'list-retry-open'));
    if (snapshot.needsImport) empty.append(button('导入恢复文件', 'primary list-retry', importFile, undefined, 'list-restore-button'));
    children.push(empty);
  }
  list.replaceChildren(...children);
  list.scrollTop = scrollTop;
  if (focusId) [...list.querySelectorAll('[data-record-id]')].find((row) => row.dataset.recordId === focusId)?.focus({ preventScroll: true });
}

function selectRecord(id) {
  selectedId = id;
  shell.dataset.view = 'detail';
  renderList();
  renderDetail();
  detail.scrollTop = 0;
  if (window.matchMedia('(max-width:640px)').matches) detail.focus({ preventScroll: true });
}

function returnToList() {
  shell.dataset.view = 'list';
  [...list.querySelectorAll('[data-record-id]')].find((row) => row.dataset.recordId === selectedId)?.focus({ preventScroll: true });
}

async function copy(value, label = '内容') {
  if (!value) { toast(`还没有填写${label}`); return; }
  try {
    if (!host?.copyText) throw new Error('clipboard_unavailable');
    await host.copyText(value);
    toast(`${label}已复制`);
  } catch { toast('复制失败，请长按或选中文本手动复制。', 'error'); }
}

function toolbar(record) {
  const bar = el('div', 'detail-toolbar');
  const start = el('div');
  const back = button('全部记录', 'mobile-back', returnToList, 'back', 'back-button');
  back.className = 'mobile-back';
  start.append(back, el('span', 'breadcrumb', record?.conflict ? '我的密码 / 处理冲突' : '我的密码 / 记录详情'));
  bar.append(start);
  if (record && !record.conflict) {
    const actions = el('div', 'detail-actions');
    actions.append(button('编辑', 'ghost', () => openEditor(record), 'edit', 'edit-button'), button('删除', 'danger-ghost', () => confirmDelete(record), 'trash', 'delete-button'));
    bar.append(actions);
  }
  return bar;
}

function fieldRow(label, value, kind, testId) {
  const row = el('div', 'field-row');
  const content = el('div', 'field-content');
  const display = el('div', `field-value${kind === 'password' ? ' password' : ''}${!value ? ' empty' : ''}`, value || '未填写');
  if (testId) display.dataset.testid = testId;
  content.append(el('span', 'field-label', label), display);
  row.append(content);
  const copyButton = button('复制', 'copy-button', () => copy(value, label), 'copy', `copy-${kind || 'username'}`);
  copyButton.className = 'copy-button';
  copyButton.setAttribute('aria-label', `复制${label}`);
  copyButton.disabled = !value;
  row.append(copyButton);
  return row;
}

function validExternalUrl(value) {
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.href : null; } catch { return null; }
}

function urlRow(value) {
  const row = el('div', 'field-row');
  const content = el('div', 'field-content');
  content.append(el('span', 'field-label', '网址'));
  const link = validExternalUrl(value);
  if (link) {
    const node = el('button', 'url-button');
    node.type = 'button';
    node.dataset.testid = 'open-url';
    node.append(el('span', 'field-value', value), icon('external', 14));
    node.addEventListener('click', async () => { try { await host.openExternal(link); } catch { toast('无法打开网址，请复制后在浏览器打开。', 'error'); } });
    content.append(node);
  } else content.append(el('div', `field-value${!value ? ' empty' : ''}`, value || '未填写'));
  row.append(content);
  const copyButton = button('复制', 'copy-button', () => copy(value, '网址'), 'copy', 'copy-url');
  copyButton.className = 'copy-button';
  copyButton.setAttribute('aria-label', '复制网址');
  copyButton.disabled = !value;
  row.append(copyButton);
  return row;
}

function renderDetail() {
  const record = snapshot.records.find((item) => item.id === selectedId);
  if (!record) {
    const empty = el('div', 'empty-state');
    const emblem = el('div', 'empty-icon');
    emblem.append(icon(fatal ? 'warning' : 'key', 31));
    empty.append(emblem, el('h2', '', fatal ? '暂时无法打开密码库' : booting ? '正在打开你的密码库' : snapshot.needsImport ? '恢复你的旧版密码库' : snapshot.records.length ? '每一条密码，都在这里' : '把密码，安心放在这里'), el('p', '', fatal ? !host ? '请从已安装的私人密码库应用打开。' : `请检查本地密码库与系统存储。
本地文件不会被自动清空。` : booting ? '正在读取此设备保存的记录…' : snapshot.needsImport ? '请导入含原密钥的密码库文件。恢复前无法编辑，旧文件会继续保留。' : snapshot.records.length ? `从左侧选择一条记录，即可查看或复制。
也可以按 Ctrl K 快速搜索。` : `保存账户与密码，在你的电脑和手机间同步。
用文件手动传递，或设置服务器自动同步。`));
    if (fatal) empty.append(button('重新打开', 'secondary', initialize, undefined, 'retry-open'));
    else if (client && snapshot.needsImport) empty.append(button('导入恢复文件', 'primary', importFile, undefined, 'restore-button'));
    else if (client && !snapshot.records.length) empty.append(button('新增第一条密码', 'primary', () => openEditor(), 'plus', 'empty-add-button'));
    detail.replaceChildren(empty);
    return;
  }
  const content = el('div', 'detail-content');
  content.append(toolbar(record));
  const heading = el('div', 'detail-heading');
  const titleContent = el('div');
  const title = el('h2', 'detail-title', recordTitle(record));
  title.dataset.testid = 'detail-title';
  titleContent.append(title, el('p', 'detail-subtitle', record.conflict ? `${record.versions.length} 个版本需要你确认` : record.entry.url || '账户与密码'));
  heading.append(el('div', 'large-avatar', avatarText(recordTitle(record))), titleContent);
  content.append(heading);
  if (record.conflict) content.append(conflictView(record));
  else {
    const fields = el('div', 'detail-fields');
    fields.append(fieldRow('账号', record.entry.username, 'username', 'detail-username'), fieldRow('密码', record.entry.password, 'password', 'detail-password'), urlRow(record.entry.url));
    content.append(fields);
    if (record.entry.notes) {
      const notes = el('div', 'notes-block');
      const label = el('div', 'notes-label');
      label.append(icon('note', 14), el('span', '', '备注'));
      const text = el('p', 'notes-text', record.entry.notes);
      text.dataset.testid = 'detail-notes';
      notes.append(label, text);
      content.append(notes);
    }
    const foot = el('div', 'detail-bottom');
    const locallySaved = !(snapshot.status === 'error' && snapshot.message?.startsWith('本地保存失败'));
    foot.append(icon('lock', 12), el('span', '', locallySaved ? `保存在此设备 · 修改于 ${formatTime(record.versions[0]?.updatedAt)}` : '尚未写入设备，请重试保存'));
    content.append(foot);
  }
  detail.replaceChildren(content);
}

function conflictView(record) {
  const container = el('div');
  const banner = el('div', 'conflict-banner');
  const label = el('strong');
  label.append(icon('warning', 17), el('span', '', '这条记录在不同设备上有修改'));
  banner.append(label, el('p', '', '请比较下面的内容，选择要保留的版本。确认后，其他版本将被丢弃并同步到所有设备。'));
  const grid = el('div', 'version-grid');
  grid.dataset.testid = 'conflict-versions';
  record.versions.forEach((version, index) => {
    const card = el('article', 'version-card');
    card.dataset.testid = 'conflict-version';
    card.dataset.versionId = version.id;
    const head = el('div', 'version-header');
    const time = el('time', '', formatTime(version.updatedAt, true));
    time.dateTime = String(version.updatedAt);
    head.append(el('h3', '', `版本 ${index + 1}${version.kind === 'delete' ? ' · 已删除' : ''}`), time);
    card.append(head);
    const body = el('div', 'version-body');
    if (version.kind === 'delete') {
      const removed = el('div', 'delete-version');
      removed.append(icon('trash', 26), el('p', '', `此版本删除了这条记录。
选择它将从所有设备移除记录。`));
      body.append(removed);
    } else {
      for (const [key, name] of [['title', '名称'], ['username', '账号'], ['password', '密码'], ['url', '网址']]) {
        const value = version.entry[key];
        const field = el('div', 'version-field');
        field.append(el('span', 'field-label', name), el('div', `field-value${key === 'password' ? ' password' : ''}${!value ? ' empty' : ''}`, value || '未填写'));
        if (value && key !== 'title') {
          const copyButton = el('button', 'icon-button version-copy');
          copyButton.type = 'button';
          copyButton.setAttribute('aria-label', `复制版本 ${index + 1} 的${name}`);
          copyButton.append(icon('copy', 16));
          copyButton.addEventListener('click', () => copy(value, name));
          field.append(copyButton);
        }
        body.append(field);
      }
      if (version.entry.notes) {
        const notes = el('div', 'version-notes');
        notes.append(el('span', 'field-label', '备注'), el('p', 'field-value', version.entry.notes));
        body.append(notes);
      }
    }
    const footer = el('div', 'version-footer');
    footer.append(button(version.kind === 'delete' ? '选择删除版本' : '保留此版本', version.kind === 'delete' ? 'secondary' : 'primary', () => confirmResolve(record, version, index), undefined, `resolve-version-${index + 1}`));
    card.append(body, footer);
    grid.append(card);
  });
  container.append(banner, grid);
  return container;
}

function onSnapshot(next) {
  snapshot = next;
  if (selectedId && !snapshot.records.some((record) => record.id === selectedId)) { selectedId = null; shell.dataset.view = 'list'; }
  const editing = modalStack.find((modal) => modal.type === 'editor');
  // A failed disk write retains the new record in the core's current session.
  // Remember its ID so pressing Save again updates that record instead of duplicating it.
  if (editing?.saving && !editing.recordId) {
    const created = snapshot.records.find((record) => !editing.existingIds.has(record.id) && record.entry && ['title', 'username', 'password', 'url', 'notes'].every((key) => record.entry[key] === (key === 'title' ? editing.draft.title.trim() : editing.draft[key])));
    if (created) editing.recordId = created.id;
  }
  if (editing?.recordId && !editing.saving && versionStamp(snapshot.records.find((record) => record.id === editing.recordId)) !== editing.baseline) {
    editing.stale = true;
    const warning = modalCard.querySelector('[data-testid="form-stale"]');
    if (warning) warning.hidden = false;
    const save = modalCard.querySelector('[data-testid="save-button"]');
    if (save) save.disabled = true;
  }
  renderStatus();
  renderList();
  renderDetail();
}

function openModal(modal) {
  if (!modalStack.length) {
    modalReturnFocus = document.activeElement;
    shell.inert = true;
  }
  modalStack.push(modal);
  layer.hidden = false;
  renderModal();
}

function closeModal() {
  modalStack.pop();
  if (modalStack.length) { renderModal(); return; }
  layer.hidden = true;
  modalCard.replaceChildren();
  shell.inert = false;
  if (modalReturnFocus?.isConnected) modalReturnFocus.focus({ preventScroll: true });
  else detail.focus({ preventScroll: true });
  modalReturnFocus = null;
}

function editorDirty(modal) {
  return ['title', 'username', 'password', 'url', 'notes'].some((key) => modal.draft[key] !== modal.original[key]);
}

function requestCloseModal() {
  const modal = modalStack.at(-1);
  if (!modal || modal.saving) return;
  if (modal.type === 'editor' && editorDirty(modal)) {
    openModal({ type: 'confirm', title: '放弃这次修改？', text: '你还没有保存编辑的内容。', confirm: '放弃修改', danger: false, testId: 'discard-confirm', onConfirm: async () => { closeModal(); closeModal(); } });
  } else closeModal();
}

function openEditor(record) {
  if (!client || snapshot.needsImport) return;
  const entry = record?.entry || { title: '', username: '', password: '', url: '', notes: '' };
  openModal({ type: 'editor', recordId: record?.id || null, existingIds: new Set(snapshot.records.map((item) => item.id)), baseline: versionStamp(record), original: { ...entry }, draft: { ...entry }, saving: false, stale: false });
}

function modalHeader(title, subtitle) {
  const head = el('div', 'modal-header');
  const content = el('div');
  const heading = el('h2', '', title);
  heading.id = 'modal-title';
  content.append(heading);
  if (subtitle) content.append(el('p', '', subtitle));
  const close = el('button', 'icon-button modal-close');
  close.type = 'button';
  close.setAttribute('aria-label', '关闭');
  close.dataset.testid = 'modal-close';
  close.append(icon('close', 18));
  close.addEventListener('click', requestCloseModal);
  head.append(content, close);
  modalCard.setAttribute('aria-labelledby', 'modal-title');
  return head;
}

function renderModal() {
  const modal = modalStack.at(-1);
  if (modal.type === 'editor') renderEditor(modal);
  else if (modal.type === 'settings') renderServerSettings(modal);
  else renderConfirm(modal);
  queueMicrotask(() => {
    if (layer.hidden) return;
    const target = modal.type === 'editor' || modal.type === 'settings' ? modalCard.querySelector('input') : modalCard.querySelector('[data-testid="confirm-cancel"]');
    (target || modalCard).focus({ preventScroll: true });
  });
}

function renderEditor(modal) {
  const form = el('form', 'entry-form');
  form.dataset.testid = 'entry-form';
  form.autocomplete = 'off';
  const fields = [
    { key: 'title', name: '名称', placeholder: '例如：个人邮箱', max: 200, required: true },
    { key: 'username', name: '账号', placeholder: '用户名或邮箱', max: 1000 },
    { key: 'password', name: '密码', placeholder: '填写密码', max: 4096 },
    { key: 'url', name: '网址', placeholder: 'https://', max: 2048 },
    { key: 'notes', name: '备注', placeholder: '其他需要记住的信息', max: 16384, multiline: true },
  ];
  for (const field of fields) {
    const wrapper = el('div', 'form-field');
    const label = el('label', '', field.name);
    label.htmlFor = `entry-${field.key}`;
    if (!field.required) label.append(el('span', 'optional-label', '选填'));
    const input = el(field.multiline ? 'textarea' : 'input', field.key === 'password' ? 'password-input' : '');
    input.id = `entry-${field.key}`;
    input.name = field.key;
    input.dataset.testid = `entry-${field.key}`;
    input.value = modal.draft[field.key];
    input.placeholder = field.placeholder;
    input.maxLength = field.max;
    input.required = !!field.required;
    input.autocomplete = field.key === 'password' ? 'new-password' : 'off';
    input.setAttribute('autocapitalize', 'none');
    input.setAttribute('autocorrect', 'off');
    input.spellcheck = field.key === 'notes';
    if (!field.multiline) input.type = 'text';
    if (field.key === 'url') input.inputMode = 'url';
    input.addEventListener('input', () => { modal.draft[field.key] = input.value; input.setCustomValidity(''); });
    wrapper.append(label, input);
    form.append(wrapper);
  }
  const stale = el('div', 'form-error form-stale', '这条记录已从其他设备更新。你的输入仍在这里，请先关闭编辑并查看最新版本。');
  stale.dataset.testid = 'form-stale';
  stale.hidden = !modal.stale;
  const error = el('div', 'form-error');
  error.dataset.testid = 'form-error';
  error.hidden = true;
  form.append(stale, error, el('p', 'form-note', snapshot.mode === 'file' ? '密码默认可见。保存到此设备后，可导出文件传给其他设备。' : '密码默认可见。保存后会先写入此设备，再自动同步。'));
  const footer = el('div', 'modal-footer');
  const cancel = button('取消', 'secondary', requestCloseModal, undefined, 'editor-cancel');
  const save = button('保存记录', 'primary', () => {}, undefined, 'save-button');
  save.type = 'submit';
  save.disabled = modal.stale;
  footer.append(cancel, save);
  form.append(footer);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (modal.saving || modal.stale) return;
    const title = modal.draft.title.trim();
    if (!title) { const input = form.querySelector('[name="title"]'); input.setCustomValidity('请填写记录名称'); input.reportValidity(); input.focus(); return; }
    modal.saving = true;
    for (const control of form.querySelectorAll('input,textarea,button')) control.disabled = true;
    modalCard.querySelector('.modal-close').disabled = true;
    save.querySelector('span').textContent = '正在保存…';
    error.hidden = true;
    try {
      const id = await client.save({ ...modal.draft, title }, modal.recordId || undefined, modal.recordId ? modal.baseline : undefined);
      selectedId = id;
      query = '';
      search.value = '';
      filter = 'all';
      modal.saving = false;
      closeModal();
      shell.dataset.view = 'detail';
      renderList();
      renderDetail();
      toast(!snapshot.configured ? '已保存在此设备' : snapshot.status === 'synced' ? '已保存并同步' : snapshot.status === 'offline' ? '已保存，联网后自动同步' : snapshot.status === 'error' ? '已保存，同步暂未完成' : '已保存，正在自动同步');
    } catch (failure) {
      modal.saving = false;
      if (failure?.code === 'stale_record') {
        modal.stale = true;
        stale.hidden = false;
      } else modal.baseline = versionStamp(snapshot.records.find((record) => record.id === modal.recordId));
      for (const control of form.querySelectorAll('input,textarea,button')) control.disabled = false;
      modalCard.querySelector('.modal-close').disabled = false;
      save.disabled = modal.stale;
      save.querySelector('span').textContent = '保存记录';
      error.textContent = errorText(failure);
      error.hidden = false;
      error.setAttribute('role', 'alert');
    }
  });
  modalCard.replaceChildren(modalHeader(modal.recordId ? '编辑记录' : '新增密码', '只需要记住在哪里找，不必记住每个密码。'), form);
}

function renderConfirm(modal) {
  const content = el('div', 'confirm-content');
  content.append(el('p', modal.danger ? 'confirm-warning' : '', modal.text));
  const error = el('div', 'form-error');
  error.dataset.testid = 'confirm-error';
  error.hidden = true;
  content.append(error);
  const footer = el('div', 'modal-footer');
  const cancel = button('取消', 'secondary', closeModal, undefined, 'confirm-cancel');
  const confirm = button(modal.confirm, modal.danger ? 'danger' : 'primary', async () => {
    if (modal.saving) return;
    modal.saving = true;
    cancel.disabled = true;
    confirm.disabled = true;
    modalCard.querySelector('.modal-close').disabled = true;
    confirm.querySelector('span').textContent = '正在处理…';
    try { await modal.onConfirm(); } catch (failure) {
      modal.saving = false;
      cancel.disabled = false;
      confirm.disabled = false;
      modalCard.querySelector('.modal-close').disabled = false;
      confirm.querySelector('span').textContent = modal.confirm;
      error.textContent = errorText(failure);
      error.hidden = false;
      error.setAttribute('role', 'alert');
    }
  }, undefined, modal.testId || 'confirm-action');
  footer.append(cancel, confirm);
  content.append(footer);
  modalCard.replaceChildren(modalHeader(modal.title), content);
}

function confirmDelete(record) {
  openModal({ type: 'confirm', title: `删除“${recordTitle(record)}”？`, text: '删除后无法恢复。其他设备联网时，也会同步删除这条记录。', confirm: '确认删除', danger: true, testId: 'confirm-delete', onConfirm: async () => {
    await client.remove(record.id);
    closeModal();
    selectedId = null;
    shell.dataset.view = 'list';
    renderList();
    renderDetail();
    toast('记录已删除');
  } });
}

function confirmResolve(record, version, index) {
  openModal({ type: 'confirm', title: version.kind === 'delete' ? '确认删除这条记录？' : `保留版本 ${index + 1}？`, text: version.kind === 'delete' ? '这条记录将从所有设备删除，其他冲突版本会被丢弃。此操作无法撤销。' : '其他冲突版本会被丢弃，你选择的内容将同步到所有设备。此操作无法撤销。', confirm: version.kind === 'delete' ? '确认删除' : '确认保留', danger: version.kind === 'delete', testId: 'confirm-resolve', onConfirm: async () => {
    await client.resolve(record.id, version.id);
    closeModal();
    renderList();
    renderDetail();
    if (version.kind === 'delete') shell.dataset.view = 'list';
    toast('冲突已处理');
  } });
}

async function synchronize(manual = false) {
  if (!client || snapshot.needsImport || (!snapshot.configured && snapshot.status !== 'error') || snapshot.status === 'syncing') return;
  try {
    await client.sync();
    if (manual) toast(!snapshot.configured && snapshot.status === 'local' ? '已保存在此设备' : snapshot.status === 'synced' ? '已与云端同步' : snapshot.status === 'offline' ? '暂时无法连接，稍后会再次同步' : snapshot.message || '同步未完成', snapshot.status === 'synced' || (!snapshot.configured && snapshot.status === 'local') ? 'success' : 'error');
  } catch (error) { if (manual) toast(errorText(error), 'error'); }
}

async function importFile() {
  if (!client || fileBusy) return;
  fileBusy = true; renderStatus();
  try {
    const text = await host.chooseImportFile();
    if (text === null) return;
    await client.importFile(text);
    if (!selectedId) selectedId = snapshot.records[0]?.id || null;
    renderList(); renderDetail();
    toast('文件已导入');
  } catch (error) { toast(errorText(error), 'error'); }
  finally { fileBusy = false; renderStatus(); }
}

async function exportFile() {
  if (!client || snapshot.needsImport || fileBusy) return;
  fileBusy = true; renderStatus();
  try {
    const text = await client.exportFile();
    if (await host.saveExportFile(text)) toast('已导出，请妥善保管文件');
  } catch (error) { toast(errorText(error), 'error'); }
  finally { fileBusy = false; renderStatus(); }
}

async function changeMode(mode) {
  if (!client || snapshot.needsImport || fileBusy || snapshot.mode === mode) return;
  if (mode === 'server' && !snapshot.serverEndpoint) { await openServerSettings(); return; }
  try { await client.setMode(mode); toast(mode === 'file' ? '已切换为文件模式' : '已开启服务器同步'); }
  catch (error) { toast(errorText(error), 'error'); }
}

async function openServerSettings() {
  if (!client || snapshot.needsImport || settingsOpening || modalStack.length) return;
  settingsOpening = true;
  try {
    const config = await host.getConfig();
    if (!config) throw { code: 'needs_import' };
    openModal({ type: 'settings', endpoint: snapshot.serverEndpoint || '', token: config.token, saving: false });
  } catch (error) { toast(errorText(error), 'error'); }
  finally { settingsOpening = false; }
}

function renderServerSettings(modal) {
  const form = el('form', 'entry-form');
  form.dataset.testid = 'server-settings-form';
  form.autocomplete = 'off';
  const endpointField = el('div', 'form-field');
  const endpointLabel = el('label', '', 'HTTPS 服务器地址'); endpointLabel.htmlFor = 'server-endpoint';
  const endpoint = el('input'); endpoint.id = 'server-endpoint'; endpoint.type = 'text'; endpoint.inputMode = 'url'; endpoint.placeholder = 'https://服务器地址'; endpoint.value = modal.endpoint; endpoint.maxLength = 2048; endpoint.required = true; endpoint.dataset.testid = 'server-endpoint';
  endpoint.setAttribute('autocapitalize', 'none'); endpoint.setAttribute('autocorrect', 'off'); endpoint.spellcheck = false;
  endpoint.addEventListener('input', () => { modal.endpoint = endpoint.value; });
  endpointField.append(endpointLabel, endpoint);
  const tokenField = el('div', 'form-field');
  const tokenLabel = el('label', '', '同步凭据 · 请勿公开'); tokenLabel.htmlFor = 'server-token';
  const tokenRow = el('div', 'token-input-row');
  const token = el('input'); token.id = 'server-token'; token.type = 'password'; token.value = modal.token; token.maxLength = 200; token.minLength = 20; token.required = true; token.autocomplete = 'new-password'; token.dataset.testid = 'server-token'; token.spellcheck = false;
  token.addEventListener('input', () => { modal.token = token.value; });
  tokenRow.append(token, button('复制', 'secondary', () => copy(modal.token, '同步凭据'), 'copy', 'copy-server-token'));
  tokenField.append(tokenLabel, tokenRow);
  const note = el('p', 'form-note', '已填入此密码库的同步凭据。服务器需要配置对应的凭据摘要；保存后启用自动同步。');
  const error = el('div', 'form-error'); error.hidden = true; error.dataset.testid = 'server-settings-error';
  const footer = el('div', 'modal-footer');
  const cancel = button('取消', 'secondary', requestCloseModal, undefined, 'settings-cancel');
  const submit = button('保存并启用', 'primary', () => {}, undefined, 'settings-save'); submit.type = 'submit';
  footer.append(cancel, submit);
  form.append(endpointField, tokenField, note, error, footer);
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (modal.saving) return;
    modal.saving = true; error.hidden = true;
    for (const control of modalCard.querySelectorAll('input,button')) control.disabled = true;
    submit.querySelector('span').textContent = '正在保存…';
    try {
      await client.configureServer({ endpoint: modal.endpoint.trim(), token: modal.token.trim() });
      await client.setMode('server');
      modal.saving = false; closeModal(); toast('已启用服务器同步');
    } catch (failure) {
      modal.saving = false;
      for (const control of modalCard.querySelectorAll('input,button')) control.disabled = false;
      submit.querySelector('span').textContent = '保存并启用';
      error.textContent = errorText(failure); error.hidden = false; error.setAttribute('role', 'alert');
    }
  });
  modalCard.replaceChildren(modalHeader('服务器同步设置', '只在服务器模式下联网同步。'), form);
}

async function initialize() {
  if (booting) return;
  booting = true;
  fatal = false;
  renderStatus();
  renderList();
  renderDetail();
  try {
    if (!host) throw new Error('host_unavailable');
    client = await createVaultClient(host);
    unsubscribe?.();
    booting = false;
    unsubscribe = client.subscribe(onSnapshot);
    if (host.__testMode === true) Object.defineProperty(window, '__vaultClient', { value: Object.freeze({ snapshot: () => client.snapshot() }), configurable: true });
    await synchronize();
  } catch (error) {
    client = null;
    booting = false;
    fatal = true;
    renderStatus();
    renderList();
    renderDetail();
    if (host) toast(errorText(error), 'error');
  }
}

$('add-button').addEventListener('click', () => openEditor());
$('sync-button').addEventListener('click', () => synchronize(true));
$('import-button').addEventListener('click', importFile);
$('export-button').addEventListener('click', exportFile);
$('settings-button').addEventListener('click', openServerSettings);
$('mode-file').addEventListener('click', () => changeMode('file'));
$('mode-server').addEventListener('click', () => changeMode('server'));
search.addEventListener('input', () => { query = search.value; renderList(); });
$('filter-all').addEventListener('click', () => { filter = 'all'; renderList(); });
$('filter-conflict').addEventListener('click', () => { filter = 'conflict'; renderList(); });
layer.addEventListener('click', (event) => { if (event.target === layer) requestCloseModal(); });
document.addEventListener('keydown', (event) => {
  if (modalStack.length) {
    if (event.key === 'Escape') { event.preventDefault(); requestCloseModal(); }
    if (event.key === 'Tab') {
      const targets = [...modalCard.querySelectorAll('button:not(:disabled),input:not(:disabled),textarea:not(:disabled),[tabindex="0"]')].filter((node) => !node.hidden && node.getClientRects().length);
      if (!targets.length) { event.preventDefault(); modalCard.focus(); return; }
      const first = targets[0]; const last = targets.at(-1);
      if (event.shiftKey && (document.activeElement === first || !modalCard.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || !modalCard.contains(document.activeElement))) { event.preventDefault(); first.focus(); }
    }
    return;
  }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); returnToList(); search.focus(); search.select(); }
  else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'n') { event.preventDefault(); openEditor(); }
  else if (event.key === 'Escape') { if (query) { query = ''; search.value = ''; renderList(); } returnToList(); }
});
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') synchronize();
  else { clearTimeout(toastTimer); $('toast').hidden = true; }
});
window.addEventListener('online', () => synchronize());
window.addEventListener('focus', () => synchronize());
window.addEventListener('vault-resume', () => synchronize());
window.addEventListener('vault-back', (event) => {
  if (modalStack.length) { event.preventDefault(); requestCloseModal(); }
  else if (shell.dataset.view === 'detail') { event.preventDefault(); returnToList(); }
  else if (query) { event.preventDefault(); query = ''; search.value = ''; renderList(); }
});
initialize();
