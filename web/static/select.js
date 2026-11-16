/*!
 * Standalone combobox, extracted from Bootstrap combobox.js v6.0.0-alpha.1 (js/dist/combobox.js)
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/main/LICENSE)
 *
 * Dependencies (Bootstrap's BaseComponent, EventHandler, SelectorEngine, Menu, util)
 * are replaced with plain DOM equivalents. Menu positioning uses absolute offsets
 * instead of Floating UI.
 *
 * Styles: .menu, .menu-item, .menu-item-check, and .combobox-* in style.css.
 * They follow Bootstrap's menu and combobox styles, using the theme variables.
 */
(() => {
	const NAME = "combobox";
	const DATA_KEY = `bs.${NAME}`;

	const ESCAPE_KEY = "Escape";
	const TAB_KEY = "Tab";
	const ARROW_UP_KEY = "ArrowUp";
	const ARROW_DOWN_KEY = "ArrowDown";
	const HOME_KEY = "Home";
	const END_KEY = "End";
	const ENTER_KEY = "Enter";
	const SPACE_KEY = " ";

	const CLASS_NAME_SHOW = "show";
	const CLASS_NAME_SELECTED = "selected";
	const CLASS_NAME_PLACEHOLDER = "combobox-placeholder";

	const SELECTOR_DATA_TOGGLE = '[data-bs-toggle="combobox"]';
	const SELECTOR_MENU = ".menu";
	const SELECTOR_MENU_ITEM = ".menu-item[data-bs-value]";
	const SELECTOR_VISIBLE_ITEMS = ".menu-item[data-bs-value]:not(.disabled):not(:disabled)";
	const SELECTOR_VALUE = ".combobox-value";
	const SELECTOR_SEARCH_INPUT = ".combobox-search-input";
	const SELECTOR_NO_RESULTS = ".combobox-no-results";

	// Instance registry, the same as Bootstrap's dom/data.js. Each element maps to
	// a key/instance map, so an element can hold only one instance per key.
	// A WeakMap replaces Bootstrap's Map so an element can be collected after it
	// leaves the document, even if its instance was never disposed.
	const elementMap = new WeakMap();

	const Data = {
		set(element, key, instance) {
			if (!elementMap.has(element)) elementMap.set(element, new Map());

			const instanceMap = elementMap.get(element);
			if (!instanceMap.has(key) && instanceMap.size !== 0) {
				console.error(
					`Combobox doesn't allow more than one instance per element. Bound instance: ${[...instanceMap.keys()][0]}.`,
				);
				return;
			}

			instanceMap.set(key, instance);
		},

		get(element, key) {
			if (element && elementMap.has(element)) {
				return elementMap.get(element).get(key) || null;
			}

			return null;
		},

		getAny(element) {
			if (element && elementMap.has(element)) {
				return elementMap.get(element).values().next().value || null;
			}

			return null;
		},

		remove(element, key) {
			if (!elementMap.has(element)) return;

			const instanceMap = elementMap.get(element);
			instanceMap.delete(key);
			if (instanceMap.size === 0) elementMap.delete(element);
		},
	};

	const isDisabled = (element) => {
		if (!element || element.nodeType !== Node.ELEMENT_NODE) return true;
		if (element.classList.contains("disabled")) return true;
		if (typeof element.disabled !== "undefined") return element.disabled;
		return element.hasAttribute("disabled") && element.getAttribute("disabled") !== "false";
	};

	const isVisible = (element) => {
		if (!element || element.getClientRects().length === 0) return false;
		return getComputedStyle(element).getPropertyValue("visibility") === "visible";
	};

	const getNextActiveElement = (list, activeElement, shouldGetNext, isCycleAllowed) => {
		const listLength = list.length;
		let index = list.indexOf(activeElement);
		if (index === -1) return !shouldGetNext && isCycleAllowed ? list[listLength - 1] : list[0];
		index += shouldGetNext ? 1 : -1;
		if (isCycleAllowed) index = (index + listLength) % listLength;
		return list[Math.max(0, Math.min(index, listLength - 1))];
	};

	const trigger = (element, event, args) => {
		const evt = Object.assign(new Event(event, { bubbles: true, cancelable: true }), args);
		element.dispatchEvent(evt);
		return evt;
	};

	const getConfig = (element) => {
		const data = element.dataset;
		const bool = (value, fallback) => (value === undefined ? fallback : value !== "false");
		return {
			multiple: bool(data.bsMultiple, false),
			name: data.bsName ?? null,
			placeholder: data.bsPlaceholder ?? "",
			search: bool(data.bsSearch, false),
			searchNormalize: bool(data.bsSearchNormalize, false),
		};
	};

	const nextMatch = (element, selector) => {
		let sibling = element.nextElementSibling;
		while (sibling && !sibling.matches(selector)) sibling = sibling.nextElementSibling;
		return sibling;
	};

	class Combobox {
		constructor(element) {
			const existingInstance = Data.get(element, DATA_KEY);
			if (existingInstance) existingInstance.dispose();
			Data.set(element, DATA_KEY, this);

			this._config = getConfig(element);
			this._toggle = element;
			this._menu = nextMatch(this._toggle, SELECTOR_MENU);
			this._valueDisplay = this._toggle.querySelector(SELECTOR_VALUE);
			this._searchInput = this._menu.querySelector(SELECTOR_SEARCH_INPUT);
			this._noResults = this._menu.querySelector(SELECTOR_NO_RESULTS);
			this._hiddenInput = null;
			this._hiddenInputCreated = false;
			// Aborting this controller removes all listeners when the instance is
			// disposed, so the element can take a fresh instance.
			this._abort = new AbortController();

			this._createHiddenInput();
			this._syncInitialSelection();
			this._addEventListeners();
		}

		static get NAME() {
			return NAME;
		}

		static get DATA_KEY() {
			return DATA_KEY;
		}

		static getInstance(element) {
			return Data.get(element, DATA_KEY);
		}

		static getOrCreateInstance(element) {
			return this.getInstance(element) || new this(element);
		}

		dispose() {
			if (this._isShown()) this._hideMenu();

			this._abort.abort();

			if (this._hiddenInputCreated && this._hiddenInput) {
				this._hiddenInput.remove();
			}

			Data.remove(this._toggle, DATA_KEY);

			this._config = null;
			this._toggle = null;
			this._menu = null;
			this._valueDisplay = null;
			this._searchInput = null;
			this._noResults = null;
			this._hiddenInput = null;
		}

		toggle() {
			return this._isShown() ? this.hide() : this.show();
		}

		show() {
			if (isDisabled(this._toggle) || this._isShown()) return;
			if (trigger(this._toggle, "show").defaultPrevented) return;

			this._showMenu();

			if (this._searchInput) {
				this._searchInput.value = "";
				this._filterItems("");
				requestAnimationFrame(() => this._searchInput.focus());
			}

			trigger(this._toggle, "shown");
		}

		hide() {
			if (!this._isShown()) return;
			if (trigger(this._toggle, "hide").defaultPrevented) return;

			this._hideMenu();
			trigger(this._toggle, "hidden");
		}

		value() {
			const value = this._hiddenInput?.value ?? "";
			if (!value) return [];
			const values = this._config.multiple ? value.split(",") : [value];
			return values.map((entry) => entry.trim()).filter(Boolean);
		}

		setValue(values) {
			const items = [...this._menu.querySelectorAll(SELECTOR_MENU_ITEM)];
			for (const item of items) {
				if (Array.isArray(values)) {
					if (values.includes(item.dataset.bsValue)) {
						this._selectItem(item);
					}
				} else {
					if (values === item.dataset.bsValue) {
						this._selectItem(item);
					}
				}
			}
		}

		_showMenu() {
			const { offsetTop, offsetLeft, offsetHeight, offsetWidth } = this._toggle;
			Object.assign(this._menu.style, {
				position: "absolute",
				top: `${offsetTop + offsetHeight + 2}px`,
				left: `${offsetLeft}px`,
				minWidth: `${offsetWidth}px`,
			});
			this._toggle.focus({ focusVisible: false });
			this._toggle.setAttribute("aria-expanded", "true");
			this._menu.classList.add(CLASS_NAME_SHOW);
			this._toggle.classList.add(CLASS_NAME_SHOW);
		}

		_hideMenu() {
			this._toggle.setAttribute("aria-expanded", "false");
			this._menu.classList.remove(CLASS_NAME_SHOW);
			this._toggle.classList.remove(CLASS_NAME_SHOW);
		}

		_isShown() {
			return this._menu.classList.contains(CLASS_NAME_SHOW);
		}

		// Refreshes the toggle label and hidden input after the menu items were
		// selected or deselected from outside the combobox.
		update() {
			this._updateToggleText();
			this._updateHiddenInput();
		}

		_createHiddenInput() {
			const { name } = this._config;
			if (!name) return;

			// A page may declare the hidden input statically so the browser
			// restores its value on reload, the same as other form controls.
			const existing = this._toggle.parentNode.querySelector(
				`:scope > input[type="hidden"][name="${CSS.escape(name)}"]`,
			);
			if (existing) {
				this._hiddenInput = existing;
				return;
			}

			this._hiddenInput = document.createElement("input");
			this._hiddenInput.type = "hidden";
			this._hiddenInput.name = name;
			this._hiddenInput.value = "";
			this._hiddenInputCreated = true;
			this._toggle.parentNode.insertBefore(this._hiddenInput, this._toggle);
		}

		_syncInitialSelection() {
			this.setValue(this.value()); // adds any items from the hidden input to the current selection
			if (this._getSelectedItems().length > 0) {
				this._updateToggleText();
				this._updateHiddenInput();
			} else {
				this._showPlaceholder();
			}
		}

		_addEventListeners() {
			const { signal } = this._abort;

			this._menu.addEventListener(
				"click",
				(event) => {
					const item = event.target.closest(SELECTOR_MENU_ITEM);
					if (!item || isDisabled(item)) return;

					event.preventDefault();
					event.stopPropagation();
					this._selectItem(item);
				},
				{ signal },
			);

			this._toggle.addEventListener(
				"keydown",
				(event) => {
					this._handleToggleKeydown(event);
				},
				{ signal },
			);

			this._menu.addEventListener(
				"keydown",
				(event) => {
					this._handleMenuKeydown(event);
				},
				{ signal },
			);

			if (this._searchInput) {
				this._searchInput.addEventListener(
					"input",
					() => {
						this._filterItems(this._searchInput.value);
					},
					{ signal },
				);

				this._searchInput.addEventListener(
					"keydown",
					(event) => {
						if (event.key === ARROW_DOWN_KEY) {
							event.preventDefault();
							const items = this._getVisibleItems();
							if (items.length > 0) items[0].focus();
						}

						if (event.key === ESCAPE_KEY) {
							this.hide();
							this._toggle.focus();
						}
					},
					{ signal },
				);
			}
		}

		_selectItem(item) {
			if (this._config.multiple) {
				item.classList.toggle(CLASS_NAME_SELECTED);
				item.setAttribute("aria-selected", String(item.classList.contains(CLASS_NAME_SELECTED)));
			} else {
				for (const prev of this._getSelectedItems()) {
					prev.classList.remove(CLASS_NAME_SELECTED);
					prev.setAttribute("aria-selected", "false");
				}

				item.classList.add(CLASS_NAME_SELECTED);
				item.setAttribute("aria-selected", "true");
			}

			this._updateToggleText();
			this._updateHiddenInput();

			const value = this._config.multiple
				? this._getSelectedItems().map((el) => el.dataset.bsValue)
				: item.dataset.bsValue;

			trigger(this._toggle, "change", { value, item });

			if (!this._config.multiple) {
				this.hide();
				this._toggle.focus();
			}
		}

		_updateToggleText() {
			const selectedItems = this._getSelectedItems();

			if (selectedItems.length === 0) {
				this._showPlaceholder();
				return;
			}

			this._valueDisplay.classList.remove(CLASS_NAME_PLACEHOLDER);

			if (this._menu.querySelector("img:first-child")) {
				this._valueDisplay.replaceChildren(
					...selectedItems.map((item) => {
						const icon = item.querySelector("img:first-child");
						return icon ? icon.cloneNode(true) : item.textContent.trim();
					}),
					document.createTextNode("\xa0"), // \xa0 is an nbsp
				);
			} else {
				if (this._config.multiple && selectedItems.length > 1) {
					this._valueDisplay.textContent = `${selectedItems.length} selected`;
				} else {
					const item = selectedItems[0];
					const label = item.querySelector(".menu-item-content > span:first-child");
					this._valueDisplay.textContent = label ? label.textContent : item.textContent.trim();
				}
			}
		}

		_showPlaceholder() {
			const { placeholder } = this._config;
			if (placeholder) {
				this._valueDisplay.textContent = placeholder;
				this._valueDisplay.classList.add(CLASS_NAME_PLACEHOLDER);
			}
		}

		_updateHiddenInput() {
			if (!this._hiddenInput) return;

			const values = this._getSelectedItems().map((el) => el.dataset.bsValue);
			this._hiddenInput.value = this._config.multiple ? values.join(",") : values[0] || "";
		}

		_getSelectedItems() {
			return [...this._menu.querySelectorAll(`.${CLASS_NAME_SELECTED}`)];
		}

		_getVisibleItems() {
			return [...this._menu.querySelectorAll(SELECTOR_VISIBLE_ITEMS)].filter((item) => isVisible(item));
		}

		_filterItems(query) {
			const normalizedQuery = this._normalizeText(query.toLowerCase().trim());
			const items = [...this._menu.querySelectorAll(SELECTOR_MENU_ITEM)];
			let visibleCount = 0;

			for (const item of items) {
				const text = this._normalizeText(item.textContent.toLowerCase().trim());
				const matches = !normalizedQuery || text.includes(normalizedQuery);
				item.style.display = matches ? "" : "none";
				if (matches) visibleCount++;
			}

			if (this._noResults) {
				this._noResults.classList.toggle("d-none", visibleCount > 0);
			}
		}

		_normalizeText(text) {
			if (this._config.searchNormalize) {
				return text.normalize("NFD").replace(/[\u0300-\u036F]/g, "");
			}

			return text;
		}

		_handleToggleKeydown(event) {
			const { key } = event;

			if (key === ARROW_DOWN_KEY || key === ARROW_UP_KEY) {
				event.preventDefault();
				if (!this._isShown()) this.show();

				const items = this._getVisibleItems();
				if (items.length > 0) {
					(key === ARROW_DOWN_KEY ? items[0] : items.at(-1)).focus();
				}

				return;
			}

			if (key === ESCAPE_KEY && this._isShown()) {
				event.preventDefault();
				this.hide();
				this._toggle.focus();
				return;
			}

			if ((key === ENTER_KEY || key === SPACE_KEY) && !this._isShown()) {
				event.preventDefault();
				this.show();
			}
		}

		_handleMenuKeydown(event) {
			const { key, target } = event;

			if (key === ESCAPE_KEY) {
				event.preventDefault();
				event.stopPropagation();
				this.hide();
				this._toggle.focus();
				return;
			}

			if (key === TAB_KEY) {
				this.hide();
				return;
			}

			const isInput = target.matches("input");

			if (key === ARROW_DOWN_KEY || key === ARROW_UP_KEY) {
				event.preventDefault();
				const items = this._getVisibleItems();
				if (items.length > 0) {
					getNextActiveElement(items, target, key === ARROW_DOWN_KEY, !items.includes(target)).focus();
				}

				return;
			}

			if (key === HOME_KEY || key === END_KEY) {
				event.preventDefault();
				const items = this._getVisibleItems();
				if (items.length > 0) {
					(key === HOME_KEY ? items[0] : items.at(-1)).focus();
				}

				return;
			}

			if ((key === ENTER_KEY || key === SPACE_KEY) && !isInput) {
				event.preventDefault();
				const item = target.closest(SELECTOR_MENU_ITEM);
				if (item && !isDisabled(item)) this._selectItem(item);
			}
		}
	}

	document.addEventListener("click", (event) => {
		for (const toggle of document.querySelectorAll(`${SELECTOR_DATA_TOGGLE}.${CLASS_NAME_SHOW}`)) {
			const instance = Combobox.getInstance(toggle);
			if (!instance || toggle.contains(event.target)) continue;

			const inMenu = instance._menu.contains(event.target);
			if (instance._config.multiple && inMenu) continue;
			if (inMenu && /input|select|option|textarea|form/i.test(event.target.tagName)) continue;

			instance.hide();
		}
	});

	document.addEventListener("click", (event) => {
		const toggle = event.target.closest(SELECTOR_DATA_TOGGLE);
		if (!toggle) return;

		event.preventDefault();
		getOrCreateInstance(toggle).toggle();
	});

	const getOrCreateInstance = (element) => Combobox.getOrCreateInstance(element);

	const init = () => {
		for (const toggle of document.querySelectorAll(SELECTOR_DATA_TOGGLE)) getOrCreateInstance(toggle);
	};

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", init);
	} else {
		init();
	}

	window.Combobox = Combobox;
})();
