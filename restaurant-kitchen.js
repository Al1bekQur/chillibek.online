const API_URL = document.documentElement.dataset.apiBase || '/api';
        function apiFetch(path, options = {}) {
            const headers = new Headers(options.headers || {});
            const token = sessionStorage.getItem('staffToken');
            if (token) headers.set('Authorization', `Bearer ${token}`);
            return fetch(`${API_URL}${path}`, { ...options, headers }).then(response => {
                if (response.status === 401 && path !== '/staff/login') {
                    sessionStorage.removeItem('staffToken');
                    window.location.reload();
                }
                return response;
            });
        }
        const D = window.RestaurantDOM;
        let fetchInterval;
        let timerInterval;
        let currentUserRole = '';

        function parseDate(dateStr) {
            if (typeof dateStr !== 'string' || !dateStr) return null;
            const date = new Date(dateStr.replace(' ', 'T') + 'Z');
            return Number.isFinite(date.getTime()) ? date : null;
        }

        function formatDateTime(dateStr) {
            const d = parseDate(dateStr);
            if (!d) return '';
            const hh = d.getHours().toString().padStart(2, '0');
            const mm = d.getMinutes().toString().padStart(2, '0');
            const DD = d.getDate().toString().padStart(2, '0');
            const MM = (d.getMonth() + 1).toString().padStart(2, '0');
            const YY = d.getFullYear().toString().slice(2);
            return `${hh}:${mm} | ${DD}.${MM}.${YY}`;
        }

        function formatTime(dateStr) {
            const d = parseDate(dateStr);
            if (!d) return '';
            const hh = d.getHours().toString().padStart(2, '0');
            const mm = d.getMinutes().toString().padStart(2, '0');
            return `${hh}:${mm}`;
        }

        function calcDuration(startStr, endStr) {
            const start = parseDate(startStr);
            const end = endStr ? parseDate(endStr) : new Date();
            if (!start || !end) return "00:00";
            let diffSec = Math.floor((end - start) / 1000);
            if (diffSec < 0) diffSec = 0;
            const m = Math.floor(diffSec / 60).toString().padStart(2, '0');
            const s = (diffSec % 60).toString().padStart(2, '0');
            return `${m}:${s}`;
        }

        async function login() {
            sessionStorage.removeItem('staffToken');
            const user = document.getElementById('username').value;
            const pass = document.getElementById('password').value;
            const err = document.getElementById('loginError');
            err.style.display = 'none';
            if (!user || !pass) { err.innerText = "Заполните все поля!"; err.style.display = 'block'; return; }

            try {
                const res = await apiFetch('/staff/login', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: user, password: pass })
                });
                const data = await res.json();

                if (res.ok && data.success) {
                    if (data.token) sessionStorage.setItem('staffToken', data.token);
                    currentUserRole = data.role;
                    document.getElementById('loginScreen').style.display = 'none';
                    document.getElementById('kitchenPanel').style.display = 'block';

                    const roleText = currentUserRole === 'waiter' ? '👤 Официант' : (currentUserRole === 'chef' ? '👨‍🍳 Повар' : 'Админ');
                    document.getElementById('roleBadge').innerText = roleText;

                    loadOrders();
                    fetchInterval = setInterval(loadOrders, 3000);
                    timerInterval = setInterval(updateTickers, 1000);
                } else {
                    err.innerText = data.message || "Доступ запрещен.";
                    err.style.display = 'block';
                }
            } catch (e) { err.innerText = "Ошибка сервера."; err.style.display = 'block'; }
        }

        function logout() {
            sessionStorage.removeItem('staffToken');
            clearInterval(fetchInterval); clearInterval(timerInterval);
            currentUserRole = ''; document.getElementById('username').value = ''; document.getElementById('password').value = '';
            document.getElementById('kitchenPanel').style.display = 'none'; document.getElementById('loginScreen').style.display = 'block';
        }

        async function loadOrders() {
            try {
                const res = await apiFetch('/orders');
                const orders = await res.json();
                renderOrders(orders);
                updateTickers();
            } catch (e) { console.error("Ошибка загрузки заказов:", e); }
        }

        function timerBadge(label, value, className, start = '') {
            const badge = D.el('div', `timer-badge ${className}`, label);
            badge.append(D.el('span', '', value));
            if (start) badge.dataset.start = start;
            return badge;
        }

        function renderOrders(records) {
            const orders = D.orders(records);
            const lists = Object.fromEntries(['pending', 'cooking', 'ready'].map(status =>
                [status, document.getElementById(`list-${status}`)]));
            Object.values(lists).forEach(list => list.replaceChildren());
            orders.forEach(order => {
                if (!lists[order.status]) return;
                const card = D.el('div', 'order-card');
                const header = D.el('div', 'order-header');
                header.append(D.el('div', 'table-badge', `Стол ${order.table_number}`),
                    D.el('div', 'order-time', `#${order.id} • ${formatTime(order.created_at)}`));
                const timers = D.el('div', 'timers-box');
                const items = D.el('div', 'order-items');
                order.items.forEach(item => {
                    const row = D.el('div', 'item-row');
                    const content = D.el('span');
                    content.append(D.el('span', 'item-qty', `${item.qty}x`), document.createTextNode(` ${item.name}`));
                    row.append(content); items.append(row);
                });
                let actions;
                const serving = ['admin', 'waiter'].includes(currentUserRole);
                if (order.status === 'pending') {
                    timers.append(timerBadge('Ожидание: ', '00:00', 'timer-active', order.created_at));
                    actions = D.el('div', serving ? 'btn-group' : 'empty-state');
                    if (serving) actions.append(
                        D.button('👍 Одобрить', 'action-btn btn-confirm', () => updateOrderStatus(order.id, 'cooking')),
                        D.button('❌ Отклонить', 'action-btn btn-reject', () => rejectOrder(order.id)));
                    else actions.textContent = 'Ждем официанта';
                } else {
                    timers.append(timerBadge('Одобрен за: ', calcDuration(order.created_at, order.approved_at), 'timer-gray'));
                    if (order.status === 'cooking') {
                        timers.append(timerBadge('Готовка: ', '00:00', 'timer-active', order.approved_at));
                        actions = ['admin', 'chef'].includes(currentUserRole)
                            ? D.button('✅ Завершить (Готово)', 'action-btn btn-cooking', () => updateOrderStatus(order.id, 'ready'))
                            : D.el('div', 'empty-state', 'Готовится поваром...');
                    } else {
                        timers.append(timerBadge('Приготовлен за: ', calcDuration(order.approved_at, order.ready_at), 'timer-gray'));
                        actions = serving
                            ? D.button('🍽️ Отдано гостю', 'action-btn btn-ready', () => updateOrderStatus(order.id, 'completed'))
                            : D.el('div', 'empty-state', 'Ждем забор официантом');
                    }
                }
                card.append(header, timers, items, actions); lists[order.status].append(card);
            });
            for (const [status, message] of Object.entries({pending: 'Новых заказов нет', cooking: 'На кухне пусто', ready: 'Все выдано'})) {
                if (!lists[status].childElementCount) lists[status].append(D.el('div', 'empty-state', message));
            }
        }

        function updateTickers() {
            document.querySelectorAll('.timer-active').forEach(badge => {
                const startStr = badge.getAttribute('data-start');
                const span = badge.querySelector('span');
                if (startStr && span) {
                    span.innerText = calcDuration(startStr, null);
                }
            });
        }

        async function updateOrderStatus(orderId, newStatus) {
            if (!D.validId(orderId) || !['cooking', 'ready', 'completed'].includes(newStatus)) return;
            try {
                const res = await apiFetch(`/orders/${orderId}`, {
                    method: 'PUT', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status: newStatus })
                });
                if (res.ok) loadOrders();
            } catch (e) { alert("Ошибка при обновлении статуса."); }
        }

        // НОВАЯ ФУНКЦИЯ: Удаление заказа официантом
        async function rejectOrder(orderId) {
            if (!D.validId(orderId)) return;
            if (!confirm("Вы уверены, что хотите отклонить этот заказ? Он исчезнет навсегда.")) return;
            try {
                const res = await apiFetch(`/orders/${orderId}`, {
                    method: 'DELETE'
                });
                if (res.ok) loadOrders(); // Мгновенно обновляем интерфейс
            } catch (e) { alert("Ошибка при отклонении заказа."); }
        }

        // --- ЛОГИКА АРХИВА ---
        async function openArchive() {
            document.getElementById('archiveModal').style.display = 'flex';
            try {
                const res = await apiFetch('/orders/archive');
                if (!res.ok) throw new Error('Archive unavailable.');
                renderArchive(await res.json());
            } catch (e) { alert('Ошибка загрузки архива'); }
        }

        function renderArchive(records) {
            const orders = D.orders(records);
            document.getElementById('archiveCount').textContent = String(orders.length);
            const list = document.getElementById('archiveList'); list.replaceChildren();
            if (!orders.length) list.append(D.el('div', 'empty-state', 'Архив пуст. Вы еще не завершили ни одного заказа.'));
            orders.forEach(order => {
                const row = D.el('div', 'archive-item');
                const details = D.el('div'); details.style.flexGrow = '1'; details.style.marginRight = '15px';
                const table = D.el('div', 'table-badge', `Стол ${order.table_number}`);
                table.style.display = 'inline-block'; table.style.marginBottom = '8px';
                details.append(table, D.el('div', 'archive-meta', formatDateTime(order.created_at)),
                    D.el('div', '', order.items.map(item => `${item.qty}x ${item.name}`).join(', ')));
                const totals = D.el('div'); totals.style.textAlign = 'right'; totals.style.minWidth = '120px';
                const price = D.el('div', '', `${order.total_price} ₸`);
                price.style.color = 'var(--primary)'; price.style.fontWeight = 'bold'; price.style.fontSize = '1.1rem'; price.style.marginBottom = '5px';
                const timer = timerBadge('Итог: ', calcDuration(order.created_at, order.ready_at), 'timer-gray');
                timer.style.display = 'inline-flex'; totals.append(price, timer);
                row.append(details, totals); list.append(row);
            });
        }

        function closeArchive() {
            document.getElementById('archiveModal').style.display = 'none';
        }

// Bind authored controls without inline handlers or string evaluation.
document.querySelector('[data-action-click="a1"]').addEventListener('click', function(event) { login() });
document.querySelector('[data-action-click="a2"]').addEventListener('click', function(event) { openArchive() });
document.querySelector('[data-action-click="a3"]').addEventListener('click', function(event) { logout() });
document.querySelector('[data-action-click="a4"]').addEventListener('click', function(event) { closeArchive() });
