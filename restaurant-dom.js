'use strict';
// Rendering and response contracts only. WAF policy and authorization stay on
// the backend; restaurant data is always text, including with XSS inspection OFF.
(() => {
  const categories = new Set(['breakfasts', 'salads', 'soups', 'main', 'pizza', 'snacks', 'drinks']);
  const text = value => typeof value === 'string' ? value
    : typeof value === 'number' && Number.isFinite(value) ? String(value) : '';
  const validId = value => Number.isSafeInteger(value) && value > 0;
  function el(tag, className = '', value = null) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== null) node.textContent = text(value);
    return node;
  }
  function button(label, className, action) {
    const node = el('button', className, label);
    node.type = 'button';
    node.addEventListener('click', action);
    return node;
  }
  function imageUrl(value) {
    if (typeof value !== 'string' || value.length > 2048 || /[\\\u0000-\u001f\u007f]/.test(value)) return null;
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol) && url.hostname && !url.username && !url.password
        ? url.href : null;
    } catch { return null; }
  }
  function setImage(node, value) {
    const url = imageUrl(value);
    if (url) node.src = url;
    else node.removeAttribute('src');
  }
  function menu(records) {
    if (!Array.isArray(records)) throw new TypeError('Invalid menu response.');
    return records.filter(item => item && typeof item === 'object' && validId(item.id) &&
      categories.has(item.category) && Number.isSafeInteger(item.price) && item.price > 0)
      .map(item => ({id: item.id, category: item.category, price: item.price,
        name: text(item.name), description: text(item.description), weight: text(item.weight),
        image_url: imageUrl(item.image_url)}));
  }
  function orders(records) {
    if (!Array.isArray(records)) throw new TypeError('Invalid orders response.');
    return records.filter(order => order && typeof order === 'object' && validId(order.id) &&
      ['pending', 'cooking', 'ready', 'completed'].includes(order.status) && Array.isArray(order.items))
      .map(order => ({id: order.id, status: order.status, table_number: text(order.table_number),
        total_price: text(order.total_price), created_at: text(order.created_at),
        approved_at: text(order.approved_at), ready_at: text(order.ready_at),
        items: order.items.filter(item => item && typeof item === 'object')
          .map(item => ({name: text(item.name), qty: text(item.qty)}))}));
  }
  window.RestaurantDOM = Object.freeze({text, validId, el, button, imageUrl, setImage, menu, orders});
})();
