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
        let globalMenuData = [];

        const categoryNames = {
            'breakfasts': '🍳 Завтраки', 'salads': '🥗 Салаты', 'soups': '🍲 Супы',
            'main': '🥩 Горячие блюда', 'pizza': '🍕 Пиццы', 'snacks': '🍟 Закуски', 'drinks': '🍹 Напитки'
        };

        // АВТОРИЗАЦИЯ
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

                if (res.ok && data.success && data.role === 'admin') {
                    if (data.token) sessionStorage.setItem('staffToken', data.token);
                    document.getElementById('loginScreen').style.display = 'none';
                    document.getElementById('adminPanel').style.display = 'block';
                    loadAdminMenu();
                } else {
                    err.innerText = data.message || "Доступ запрещен.";
                    err.style.display = 'block';
                }
            } catch (e) { err.innerText = "Ошибка сервера."; err.style.display = 'block'; }
        }

        function logout() {
            sessionStorage.removeItem('staffToken');
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
            document.getElementById('adminPanel').style.display = 'none';
            document.getElementById('loginScreen').style.display = 'block';
        }

        // ЗАГРУЗКА МЕНЮ
        async function loadAdminMenu() {
            try {
                const res = await apiFetch('/menu');
                if (!res.ok) throw new Error('Menu unavailable.');
                globalMenuData = D.menu(await res.json());
                renderCategorizedMenu();
            } catch (e) { console.error("Ошибка загрузки:", e); }
        }

        function renderCategorizedMenu() {
            globalMenuData = D.menu(globalMenuData);
            const container = document.getElementById('menuCategoriesContainer');
            container.replaceChildren();
            for (const cat of Object.keys(categoryNames)) {
                const items = globalMenuData.filter(item => item.category === cat);
                if (!items.length) continue;
                const list = D.el('div', 'menu-list');
                items.forEach(item => {
                    const row = D.el('div', 'menu-row');
                    const details = D.el('div', 'item-details');
                    details.append(D.el('h4', '', item.name), D.el('p', '', `${item.price} ₸ • ${item.weight}`));
                    const controls = D.el('div', 'row-controls');
                    controls.append(D.button('Редактировать', 'edit-btn', () => openEditModal(item.id)),
                        D.button('Удалить', 'delete-btn', () => deleteItem(item.id)));
                    row.append(details, controls); list.append(row);
                });
                container.append(D.el('div', 'category-header', categoryNames[cat]), list);
            }
        }

        // 1. ДОБАВЛЕНИЕ
        async function validateAndAdd() {
            const err = document.getElementById('addError');
            const data = {
                category: document.getElementById('newCat').value,
                name: document.getElementById('newName').value.trim(),
                description: document.getElementById('newDesc').value.trim(),
                weight: document.getElementById('newWeight').value.trim(),
                price: document.getElementById('newPrice').value.trim(),
                image_url: document.getElementById('newImg').value.trim()
            };

            if (!data.name || !data.description || !data.weight || !data.price || !data.image_url) {
                err.innerText = "Пожалуйста, заполните все поля!";
                err.style.display = 'block';
                return;
            }
            err.style.display = 'none';

            try {
                const res = await apiFetch('/menu/add', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (res.ok) {
                    // Очищаем форму и обновляем список
                    document.getElementById('newName').value = '';
                    document.getElementById('newDesc').value = '';
                    document.getElementById('newWeight').value = '';
                    document.getElementById('newPrice').value = '';
                    document.getElementById('newImg').value = '';
                    loadAdminMenu();
                } else {
                    const failure = await res.json().catch(() => ({}));
                    err.textContent = D.text(failure.message) || 'Не удалось сохранить блюдо.';
                    err.style.display = 'block';
                }
            } catch (e) { alert("Ошибка при добавлении."); }
        }

        // 2. УДАЛЕНИЕ
        async function deleteItem(id) {
            const item = globalMenuData.find(menuItem => menuItem.id === id);
            if (!item) return;
            // Запрашиваем подтверждение, чтобы случайно не кликнуть
            if (!confirm(`Вы точно хотите удалить "${item.name}" из меню?`)) return;

            try {
                const res = await apiFetch(`/menu/delete/${id}`, { method: 'DELETE' });
                if (res.ok) loadAdminMenu();
            } catch (e) { alert("Ошибка при удалении."); }
        }

        // 3. СОХРАНЕНИЕ РЕДАКТИРОВАНИЯ
        async function saveEdit() {
            const id = Number(document.getElementById('editId').value);
            if (!D.validId(id)) return;
            const data = {
                category: document.getElementById('editCat').value,
                name: document.getElementById('editName').value.trim(),
                description: document.getElementById('editDesc').value.trim(),
                weight: document.getElementById('editWeight').value.trim(),
                price: document.getElementById('editPrice').value.trim(),
                image_url: document.getElementById('editImg').value.trim()
            };

            try {
                const res = await apiFetch(`/menu/edit/${id}`, {
                    method: 'PUT', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (res.ok) {
                    closeEditModal();
                    loadAdminMenu(); // Обновляем список на экране
                }
            } catch (e) { alert("Ошибка при сохранении."); }
        }

        // ПОИСК
        function handleSearch(query) {
            const resultsBox = document.getElementById('searchResults');
            resultsBox.replaceChildren();
            query = D.text(query);
            if (!query.length) { resultsBox.style.display = 'none'; return; }
            const matches = globalMenuData.filter(item => item.name.toLowerCase().includes(query.toLowerCase()));
            matches.forEach(item => {
                const row = D.el('div', 'search-result-item');
                row.addEventListener('click', () => openEditFromSearch(item.id));
                const name = D.el('span'); name.append(D.el('strong', '', item.name));
                const price = D.el('span', '', `${item.price} ₸`);
                price.style.color = 'var(--text-muted)'; price.style.fontSize = '0.85rem';
                row.append(name, price); resultsBox.append(row);
            });
            if (!matches.length) resultsBox.append(D.el('div', 'search-result-item', 'Ничего не найдено'));
            resultsBox.style.display = 'block';
        }

        function openEditFromSearch(id) {
            document.getElementById('searchResults').style.display = 'none';
            document.getElementById('searchInput').value = '';
            openEditModal(id);
        }

        function openEditModal(id) {
            const item = globalMenuData.find(m => m.id === id);
            if (!item) return;
            document.getElementById('editId').value = item.id;
            document.getElementById('editCat').value = item.category;
            document.getElementById('editName').value = item.name;
            document.getElementById('editDesc').value = item.description;
            document.getElementById('editWeight').value = item.weight;
            document.getElementById('editPrice').value = item.price;
            document.getElementById('editImg').value = item.image_url;
            document.getElementById('editModal').style.display = 'flex';
        }

        function closeEditModal() { document.getElementById('editModal').style.display = 'none'; }

        document.addEventListener('click', function(e) {
            if (!e.target.closest('.search-box')) { document.getElementById('searchResults').style.display = 'none'; }
        });

// Bind authored controls without inline handlers or string evaluation.
document.querySelector('[data-action-click="a1"]').addEventListener('click', function(event) { login() });
document.querySelector('[data-action-input="a2"]').addEventListener('input', function(event) { handleSearch(this.value) });
document.querySelector('[data-action-click="a3"]').addEventListener('click', function(event) { logout() });
document.querySelector('[data-action-click="a4"]').addEventListener('click', function(event) { validateAndAdd() });
document.querySelector('[data-action-click="a5"]').addEventListener('click', function(event) { if(event.target === this) closeEditModal() });
document.querySelector('[data-action-click="a6"]').addEventListener('click', function(event) { closeEditModal() });
document.querySelector('[data-action-click="a7"]').addEventListener('click', function(event) { saveEdit() });
