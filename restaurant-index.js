const API_URL = document.documentElement.dataset.apiBase || '/api';
        const D = window.RestaurantDOM;
        const categories = ['breakfasts', 'salads', 'soups', 'main', 'pizza', 'snacks', 'drinks'];
        let menuData = [];
        let cart = Object.create(null);
        let currentDetailsId = null;

        async function loadMenu() {
            try {
                const res = await fetch(`${API_URL}/menu`);
                if (!res.ok) throw new Error('Menu unavailable.');
                menuData = D.menu(await res.json());
                renderMenu();
            } catch (e) { alert("Ошибка загрузки меню."); }
        }

        function quantityControls(item, qty) {
            const change = delta => event => { event.stopPropagation(); updateCart(item.id, delta); };
            if (qty === 0) return D.button('＋', 'add-btn', change(1));
            const controls = D.el('div', 'qty-control');
            controls.addEventListener('click', event => event.stopPropagation());
            const plus = D.button('＋', 'qty-btn', change(1));
            plus.disabled = qty >= 99;
            controls.append(D.button('−', 'qty-btn', change(-1)), D.el('span', 'qty-val', qty), plus);
            return controls;
        }

        function renderMenu() {
            menuData = D.menu(menuData);
            categories.forEach(cat => document.getElementById(`items-${cat}`).replaceChildren());
            menuData.forEach(item => {
                const card = D.el('div', 'menu-item');
                const image = D.el('img', 'item-img');
                image.loading = 'lazy'; image.alt = item.name; D.setImage(image, item.image_url);
                image.addEventListener('click', () => openDetails(item.id));
                const info = D.el('div', 'item-info');
                const header = D.el('div', 'item-header');
                const title = D.el('h3', 'item-name', item.name);
                title.addEventListener('click', () => openDetails(item.id));
                header.append(title, D.el('span', 'item-weight', item.weight));
                const description = D.el('p', 'item-desc', item.description);
                description.addEventListener('click', () => openDetails(item.id));
                const prices = D.el('div', 'price-row');
                const controls = D.el('div'); controls.id = `btn-container-${item.id}`;
                controls.append(quantityControls(item, cart[item.id] || 0));
                prices.append(D.el('div', 'item-price', `${item.price} ₸`), controls);
                info.append(header, description, prices); card.append(image, info);
                document.getElementById(`items-${item.category}`).append(card);
            });
        }

        function updateCart(id, delta) {
            if (!D.validId(id) || ![-1, 1].includes(delta) || !menuData.some(item => item.id === id)) return;
            if ((cart[id] || 0) >= 99 && delta > 0) return;
            if (!cart[id]) cart[id] = 0;
            cart[id] += delta;
            if (cart[id] <= 0) delete cart[id];
            renderMenu(); updateCartUI(); updateDetailsControls();
        }

        function updateCartUI() {
            let totalItems = 0; let subtotal = 0;
            const cartList = document.getElementById('cartItemsList');
            cartList.replaceChildren();
            Object.keys(cart).forEach(id => {
                const item = menuData.find(m => m.id === Number(id));
                const qty = cart[id];
                if (!item || !Number.isSafeInteger(qty) || qty < 1 || qty > 99) { delete cart[id]; return; }
                totalItems += qty; subtotal += item.price * qty;
                const row = D.el('div', 'cart-item');
                const info = D.el('div');
                info.append(D.el('div', 'cart-item-name', item.name), D.el('div', 'cart-item-price', `${item.price} ₸`));
                row.append(info, quantityControls(item, qty)); cartList.append(row);
            });

            const service = Math.round(subtotal * 0.10);
            const total = subtotal + service;

            document.getElementById('subtotalPrice').innerText = `${subtotal} ₸`;
            document.getElementById('servicePrice').innerText = `${service} ₸`;
            document.getElementById('totalPrice').innerText = `${total} ₸`;

            const floatingCart = document.getElementById('floatingCart');
            if (totalItems > 0) {
                floatingCart.style.display = 'flex';
                document.getElementById('cartBadge').innerText = totalItems;
            } else {
                floatingCart.style.display = 'none';
                if (document.getElementById('cartModal').style.display === 'flex') { closeModalWithAnim('cartModal', 'cartContent'); }
            }
        }

        // ОТПРАВКА ЗАКАЗА НА СЕРВЕР
        async function submitOrder() {
            const tableSelect = document.getElementById('tableSelect');
            if (!tableSelect.value) {
                alert("Пожалуйста, выберите номер вашего столика!");
                return;
            }

            // Формируем список блюд
            const orderItems = [];
            let subtotal = 0;
            Object.keys(cart).forEach(id => {
                const item = menuData.find(m => m.id == id);
                const qty = cart[id];
                orderItems.push({ id: item.id, qty: qty });
                subtotal += item.price * qty;
            });

            const service = Math.round(subtotal * 0.10);
            const total = subtotal + service;

            const payload = {
                table_number: tableSelect.value,
                items: orderItems,
                total_price: total
            };

            try {
                const res = await fetch(`${API_URL}/orders`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (res.ok) {
                    alert('Ваш заказ отправлен! Ожидайте подтверждения от официанта.');
                    cart = Object.create(null); // Очищаем корзину
                    tableSelect.value = ""; // Сбрасываем столик
                    updateCartUI();
                    renderMenu();
                    closeModalWithAnim('cartModal', 'cartContent');
                }
            } catch (e) { alert("Ошибка отправки заказа. Проверьте интернет."); }
        }

        function lockScroll() { document.body.style.position = 'fixed'; document.body.style.top = `-${window.scrollY}px`; document.body.style.width = '100%'; }
        function unlockScroll() { const scrollY = document.body.style.top; document.body.style.position = ''; document.body.style.top = ''; document.body.style.width = ''; if (scrollY) { window.scrollTo(0, parseInt(scrollY) * -1); } }

        function toggleCart() {
            const modal = document.getElementById('cartModal');
            if (modal.style.display === 'flex') { closeModalWithAnim('cartModal', 'cartContent'); }
            else { modal.style.display = 'flex'; document.getElementById('cartContent').style.transform = ''; lockScroll(); }
        }

        function openDetails(id) {
            const item = menuData.find(m => m.id === id);
            if (!D.validId(id) || !item) return;
            currentDetailsId = id; D.setImage(document.getElementById('detailsImg'), item.image_url);
            document.getElementById('detailsTitle').innerText = item.name;
            document.getElementById('detailsWeight').innerText = item.weight;
            document.getElementById('detailsDesc').innerText = item.description;
            document.getElementById('detailsPrice').innerText = item.price + ' ₸';
            updateDetailsControls();
            document.getElementById('itemDetailsModal').style.display = 'flex'; document.getElementById('detailsContent').style.transform = ''; lockScroll();
        }

        function closeDetails() { closeModalWithAnim('itemDetailsModal', 'detailsContent'); currentDetailsId = null; }

        function closeModalWithAnim(modalId, contentId) {
            const content = document.getElementById(contentId);
            content.style.transition = 'transform 0.3s ease-in'; content.style.transform = 'translateY(100%)'; unlockScroll();
            setTimeout(() => { document.getElementById(modalId).style.display = 'none'; content.style.transition = ''; }, 300);
        }

        function updateDetailsControls() {
            if (currentDetailsId === null) return;
            const item = menuData.find(m => m.id === currentDetailsId);
            const container = document.getElementById('detailsControls');
            container.replaceChildren();
            if (!item) return;
            const qty = cart[item.id] || 0;
            if (qty === 0) {
                const add = D.button('＋ В корзину', 'order-btn', () => updateCart(item.id, 1));
                add.style.marginTop = '0'; add.style.padding = '12px 24px'; add.style.width = 'auto';
                container.append(add);
            } else container.append(quantityControls(item, qty));
        }

        function scrollToSection(sectionId, btn) {
            document.querySelectorAll('.category-btn').forEach(b => b.classList.remove('active')); btn.classList.add('active');
            const target = document.getElementById(`section-${sectionId}`); if (target) { target.scrollIntoView({ behavior: 'smooth' }); }
        }

        document.getElementById('cartModal').addEventListener('touchmove', e => { if (e.target === document.getElementById('cartModal')) { if (e.cancelable) e.preventDefault(); } }, {passive: false});
        document.getElementById('itemDetailsModal').addEventListener('touchmove', e => { if (e.target === document.getElementById('itemDetailsModal')) { if (e.cancelable) e.preventDefault(); } }, {passive: false});

        function makeSwipeable(modalId, contentId, closeFunc) {
            const content = document.getElementById(contentId);
            let startY = 0; let currentY = 0; let isDragging = false;
            content.addEventListener('touchstart', e => { if (content.scrollTop > 0) return; startY = e.touches[0].clientY; isDragging = true; content.style.transition = 'none'; }, {passive: true});
            content.addEventListener('touchmove', e => {
                if (!isDragging) return; currentY = e.touches[0].clientY; const deltaY = currentY - startY;
                if (deltaY > 0 && content.scrollTop <= 0) { if (e.cancelable) e.preventDefault(); content.style.transform = `translateY(${deltaY}px)`; }
            }, {passive: false});
            content.addEventListener('touchend', e => {
                if (!isDragging) return; isDragging = false; const deltaY = currentY - startY; content.style.transition = 'transform 0.3s ease-out';
                if (deltaY > 100 && content.scrollTop <= 0) { closeFunc(); } else { content.style.transform = ''; }
            });
        }

        window.onload = () => { loadMenu(); makeSwipeable('itemDetailsModal', 'detailsContent', closeDetails); makeSwipeable('cartModal', 'cartContent', toggleCart); };

// Bind authored controls without inline handlers or string evaluation.
document.querySelector('[data-action-click="a1"]').addEventListener('click', function(event) { scrollToSection('breakfasts', this) });
document.querySelector('[data-action-click="a2"]').addEventListener('click', function(event) { scrollToSection('salads', this) });
document.querySelector('[data-action-click="a3"]').addEventListener('click', function(event) { scrollToSection('soups', this) });
document.querySelector('[data-action-click="a4"]').addEventListener('click', function(event) { scrollToSection('main', this) });
document.querySelector('[data-action-click="a5"]').addEventListener('click', function(event) { scrollToSection('pizza', this) });
document.querySelector('[data-action-click="a6"]').addEventListener('click', function(event) { scrollToSection('snacks', this) });
document.querySelector('[data-action-click="a7"]').addEventListener('click', function(event) { scrollToSection('drinks', this) });
document.querySelector('[data-action-click="a8"]').addEventListener('click', function(event) { toggleCart() });
document.querySelector('[data-action-click="a9"]').addEventListener('click', function(event) { if(event.target === this) toggleCart() });
document.querySelector('[data-action-click="a10"]').addEventListener('click', function(event) { toggleCart() });
document.querySelector('[data-action-click="a11"]').addEventListener('click', function(event) { submitOrder() });
document.querySelector('[data-action-click="a12"]').addEventListener('click', function(event) { if(event.target === this) closeDetails() });
document.querySelector('[data-action-click="a13"]').addEventListener('click', function(event) { closeDetails() });
