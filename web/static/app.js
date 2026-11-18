const statusEl = document.getElementById("status");
const cancelBtn = document.getElementById("cancel-btn");
const clearAllBtn = document.getElementById("clear-all-btn");
const fileInput = document.getElementById("file-input");
const dropZone = document.getElementById("drop-zone");
const maxDistInput = document.getElementById("max-dist");
const exactOnlyInput = document.getElementById("exact-only");
const includeAHash = document.getElementById("include-ahash");
const resultsEl = document.getElementById("results");
const domainFilterItems = document.getElementById("domains");
const domainFilter = document.getElementById("domains-button");
const domainFilterClear = document.getElementById("domain-filter-clear");
const checkDuplicates = document.getElementById("check-duplicates");
const version = document.querySelector('meta[name="static-version"]').content;
const noImageURL = `static/no-image.svg?v=${version}`;
const checkURL = `static/check.svg?v=${version}`;
const hashWorkerURL = `static/hash-worker.js?v=${version}`;

const hashWorkerCount = 4;
const hashBatchSize = 8;
// Canonical hash-kind order, strongest first. Cards display the reverse order
// (ahash, dhash, phash); row matching prefers the strongest hash first.
const HASH_KINDS = ["phash", "dhash", "ahash"];
const DISPLAY_HASH_KINDS = [...HASH_KINDS].reverse();
const supportedFileName = /\.(jpe?g|png|gif|webp|bmp|tiff?|zip|cbz|rar|cbr)$/i;

let domains = [];
const selectedDomains = new Set();

// Each run starts its own hash workers and terminates them when the run ends.
const hashRequests = new Map();
let nextHashId = 1;
let activeRun = null;
// Drops during a run join it; otherwise a drop starts a new run. cancelAll aborts the active run.
let runController = new AbortController();

// Every open search, so a change can refresh the ones showing the changed IDs.
const openSearches = new Set();
// Every open search card, including cards that are still hashing and so are not
// in openSearches yet, so they can be dismissed and release their previews.
const resultStates = new Set();

// Drag state for grouping IDs: the card currently being dragged.
let cardDrag = null;
let groupSuggestionSeq = 0;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function create(tag, className = "", text) {
	const node = document.createElement(tag);
	if (className) node.className = className;
	if (text != null) node.textContent = text;
	return node;
}

function setAttrs(node, attrs) {
	for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const abortError = () => new DOMException("Cancelled", "AbortError");
const hasFiles = (e) => e.dataTransfer?.types?.includes("Files");
const getCombobox = () => window.Combobox.getOrCreateInstance(domainFilter);

// Card-local status lines share markup, one live region and one error convention.
// setStatusText never assigns className, so a status line keeps its layout class.
function setStatusText(el, text, isError = false) {
	el.textContent = text;
	el.classList.toggle("error", isError);
}

function createStatusLine(className = "", tag = "p") {
	return create(tag, className ? `status ${className}` : "status");
}

// ---------------------------------------------------------------------------
// Hash workers
// ---------------------------------------------------------------------------

function startHashWorker() {
	const worker = new Worker(hashWorkerURL);
	const ready = new Promise((resolve, reject) => {
		worker.onmessage = (e) => {
			const { id, ok, result, error } = e.data;
			if (id === 0) {
				if (ok) resolve();
				else reject(new Error(error));
				return;
			}
			const request = hashRequests.get(id);
			hashRequests.delete(id);
			if (ok) request.resolve(result);
			else request.reject(new Error(error));
		};
		worker.onerror = (e) => reject(new Error(e.message || "hasher worker failed to load"));
	});
	return { worker, ready };
}

function stopHashWorker(worker) {
	worker.terminate();
	for (const [id, request] of hashRequests) {
		if (request.worker !== worker) continue;
		hashRequests.delete(id);
		request.reject(abortError());
	}
}

async function dispatchHash(run, file) {
	const { worker } = run.workers[run.nextWorker++ % run.workers.length];
	const start = performance.now();
	try {
		await run.ready;
		if (run.finished) throw abortError();
		const id = nextHashId++;
		const hash = await new Promise((resolve, reject) => {
			hashRequests.set(id, { resolve, reject, worker });
			worker.postMessage({ id, file });
		});
		return { hash, hashMs: performance.now() - start };
	} catch (error) {
		return { error };
	}
}

// ---------------------------------------------------------------------------
// Hash values
// ---------------------------------------------------------------------------

function popcount(x) {
	let count = 0;
	while (x > 0n) {
		x &= x - 1n;
		count++;
	}
	return count;
}

// Search hashes are hex; stored hashes are decimal uint64s (quoted when huge).
function parseHash(value, radix) {
	try {
		const n = radix === 16 ? BigInt(`0x${value}`) : BigInt(value);
		return { n, bits: n.toString(2).padStart(64, "0") };
	} catch {
		return null;
	}
}

// uint64 hashes exceed the precision of a JSON number above 2^53, so keep the
// server's hash values as strings and parse them with BigInt instead.
function parseHashJSON(text) {
	return JSON.parse(text.replace(/("Hash"\s*:\s*)(\d{16,})/g, '$1"$2"'));
}

// 64-bit hash as 16 hex digits in readable groups.
function formatHash(value) {
	if (value == null || value === "") return "—";
	try {
		return BigInt(value).toString(16).padStart(16, "0").match(/.{1,4}/g).join(" ");
	} catch {
		return String(value);
	}
}

function currentMaxDistance() {
	const max = Number.isInteger(maxDistInput.valueAsNumber) ? maxDistInput.valueAsNumber : 8;
	return Math.min(8, Math.max(0, max));
}

// Each top bit sits directly above the matching bottom bit. Differing columns are marked.
function renderBitCompare(top, bottom) {
	const bytes = create("div", "bit-bytes");
	if (!top.bits || !bottom.bits) {
		bytes.textContent = "—";
		return bytes;
	}
	const length = Math.max(top.bits.length, bottom.bits.length);
	for (let start = 0; start < length; start += 8) {
		const byte = create("span", "bit-byte");
		for (let i = start; i < Math.min(start + 8, length); i++) {
			const pair = create("span", "bit-pair");
			if (top.bits[i] !== bottom.bits[i]) pair.classList.add("bit-diff");
			pair.append(top.bits[i], create("br"), bottom.bits[i]);
			byte.appendChild(pair);
		}
		bytes.appendChild(byte);
	}
	return bytes;
}

function makeHashCompare(kind, hint, distance, bitCompare) {
	const block = create("div", "hash-compare");
	const head = create("div", "hash-compare-head");
	head.append(create("span", "hash-kind", kind || "—"), create("span", "bit-hint", hint));
	if (distance != null) head.append(create("span", "hash-distance", distance));
	block.appendChild(head);
	if (bitCompare) block.appendChild(bitCompare);
	return block;
}

async function compareStored(id, searchHash, panel) {
	panel.classList.remove("error");
	try {
		const params = new URLSearchParams({ domain: id.Domain, id: id.ID });
		const response = await fetch(`get_cover_hash?${params}`);
		const data = parseHashJSON(await response.text());
		if (!response.ok) throw new Error(data.msg || response.statusText);
		const results = data.results || [];
		if (results.length === 0) {
			setStatusText(panel, "No hashes");
			return;
		}
		const list = create("div", "hash-compares");
		for (const { Hash: { Kind: kind, Hash: value } } of results) {
			const stored = parseHash(value, 10);
			const search = parseHash(searchHash[kind], 16);
			const distance = search && stored ? `distance ${popcount(search.n ^ stored.n)}` : "distance —";
			list.appendChild(makeHashCompare(kind, "search over stored", distance, renderBitCompare(search, stored)));
		}
		panel.replaceChildren(list);
	} catch (err) {
		setStatusText(panel, `Error: ${err.message}`, true);
	}
}

// ---------------------------------------------------------------------------
// IDs
// ---------------------------------------------------------------------------

function idLabel(id) {
	if (!id) return "—";
	return `${id.Domain ?? ""}:${id.ID ?? ""}`;
}

function idKey(id) {
	return `${id.Domain}:${id.ID}`;
}

// Canonical order for ID references: source, then numeric issue ID. Everything
// that lists IDs (entries, chips, summaries, rows) uses this one comparator.
function compareIDs(a, b) {
	return a.Domain.localeCompare(b.Domain) || a.ID.localeCompare(b.ID, undefined, { numeric: true });
}

// Distinct sources in canonical order, used for column headers and grid rows.
function domainsOf(entries) {
	return [...new Set(entries.map((entry) => entry.ID.Domain))].sort((a, b) => a.localeCompare(b));
}

function sourceURL(domain, id) {
	switch (domain) {
		case "comicvine.gamespot.com":
			return `https://comicvine.gamespot.com/cv/4000-${encodeURIComponent(id)}/`;
		case "metron.cloud":
			return `https://metron.cloud/issue/${encodeURIComponent(id)}/`;
		default:
			return null;
	}
}

function makeDomainIcon(domain) {
	const img = create("img");
	Object.assign(img, {
		width: 16,
		height: 16,
		loading: "lazy",
		referrerPolicy: "no-referrer",
		alt: domain,
		title: domain,
	});
	img.addEventListener("error", () => {
		const looksLikeHostname = domain.includes(".") && !/\s|\//.test(domain);
		if (img.dataset.fallbackTried || !looksLikeHostname) {
			img.replaceWith(create("span", "domain-name", domain));
			return;
		}
		img.dataset.fallbackTried = "true";
		img.src = `https://${encodeURIComponent(domain)}/favicon.ico`;
	});
	img.src = `static/${encodeURIComponent(domain)}.ico?v=${version}`;
	return img;
}

function setCoverSource(img, url) {
	if (url !== noImageURL) {
		delete img.dataset.noImage;
	} else if (img.dataset.noImage) {
		return;
	} else {
		console.log("replacing", img.src, "with the fallback image");
		img.dataset.noImage = "true";
	}
	img.src = url;
}

function makeCover(url, alt) {
	const img = create("img", "cover-thumb");
	Object.assign(img, { alt, title: alt, referrerPolicy: "no-referrer", draggable: false, loading: "lazy" });
	img.addEventListener("error", () => setCoverSource(img, noImageURL));
	setCoverSource(img, url || noImageURL);
	return img;
}

function idLink(domain, id) {
	const url = sourceURL(domain, id);
	const node = create(url ? "a" : "span");
	node.title = domain || "";
	if (url) {
		node.href = url;
		node.target = "_blank";
		node.rel = "noopener noreferrer";
	}
	if (domain) node.append(makeDomainIcon(domain), " ");
	node.append(url || !domain ? id : `${domain} ${id}`);
	return node;
}

// ---------------------------------------------------------------------------
// Domain filter
// ---------------------------------------------------------------------------

async function loadDomains() {
	const response = await fetch("domains");
	if (!response.ok) throw new Error(response.statusText);
	const lines = (await response.text()).split("\n");
	return [...new Set(lines)].sort();
}

function renderDomainFilter() {
	domainFilterItems.replaceChildren(
		...domains.map((domain) => {
			const option = create("button", "menu-item");
			option.type = "button";
			option.dataset.bsValue = domain;
			const check = create("img", "menu-item-check");
			check.src = checkURL;
			option.append(makeDomainIcon(domain), domain, check);
			return option;
		}),
	);
	getCombobox().setValue([...selectedDomains]);
}

const domainsReady = loadDomains()
	.then((list) => {
		domains = list;
		renderDomainFilter();
	})
	.catch((err) => {
		setStatusText(statusEl, `Failed to load domains: ${err.message}`, { error: true })
		domains = [];
	});

function cardMatchesFilter(card) {
	if (!includeAHash.checked && !card.Matches.some((m) => m.Hash.Kind !== "ahash")) return false;
	if (selectedDomains.size === 0) return true;
	return [card.ID, ...card.EquivalentIDs].some((eid) => selectedDomains.has(eid.Domain));
}

function reFilterResults() {
	for (const search of openSearches) search.applyFilter();
}

// Every option that changes what a search asks the server re-runs the open searches.
function refreshSearches() {
	for (const search of openSearches) search.refresh();
	reFilterResults();
}

for (const input of [exactOnlyInput, maxDistInput, includeAHash]) {
	input.addEventListener("change", refreshSearches);
}

domainFilter.addEventListener("change", () => {
	selectedDomains.clear();
	for (const item of getCombobox().value()) selectedDomains.add(item);
	reFilterResults();
});

domainFilterClear.addEventListener("click", () => {
	selectedDomains.clear();
	getCombobox().setValue([]);
	reFilterResults();
});

// ---------------------------------------------------------------------------
// Grouping IDs
// ---------------------------------------------------------------------------

// Calls an endpoint that reports its outcome in the JSON "msg" field.
// A 204 response has no body; an error is reported as a non-2xx status.
async function callIDEndpoint(endpoint, params) {
	const response = await fetch(`${endpoint}?${params}`);
	let msg = "";
	try {
		msg = (await response.json())?.msg ?? "";
	} catch {
		// No body (e.g. 204 No Content)
	}
	if (!response.ok) throw new Error(msg || response.statusText);
	return msg;
}

function associateIDs(existingID, newDomain, newID) {
	return callIDEndpoint(
		"associate_ids",
		new URLSearchParams({
			domain: existingID.Domain ?? "",
			id: existingID.ID ?? "",
			newDomain,
			newID,
		}),
	);
}

function disassociateID(id) {
	return callIDEndpoint("disassociate_id", new URLSearchParams({ domain: id.Domain ?? "", id: id.ID ?? "" }));
}

// Refreshes the search that made a change and every other open search showing one of the changed IDs.
function refreshAffected(ids, origin) {
	const keys = new Set(ids.map(idKey));
	const refreshes = new Set([origin]);
	for (const search of openSearches) {
		if (search.candidateIDs.some((eid) => keys.has(idKey(eid)))) refreshes.add(() => search.refresh());
	}
	return Promise.all([...refreshes].map((refresh) => refresh()));
}

// Groups existingID with newID. The server reports failures as 200 with the
// error in msg, so only "New ID added" counts as success. The search is then
// re-queried so the server's grouping is reflected instead of merging locally.
async function groupIDs(existingID, newID, statusLine, refreshMatches, { successText = "Grouped", onGrouped } = {}) {
	setStatusText(statusLine, "Grouping…");
	try {
		const msg = await associateIDs(existingID, newID.Domain, newID.ID);
		if (msg !== "New ID added") {
			setStatusText(statusLine, msg, true);
			return;
		}
		onGrouped?.();
		setStatusText(statusLine, successText);
		await refreshAffected([existingID, newID], refreshMatches);
	} catch (err) {
		setStatusText(statusLine, err.message, true);
	}
}

// Disassociates an ID from its group, then refreshes the search so former
// group members are no longer shown as equivalents of it.
function makeUngroupButton(id, refreshMatches, statusLine) {
	const btn = create("button", "chip-remove", "×");
	btn.type = "button";
	btn.addEventListener("click", async () => {
		btn.disabled = true;
		try {
			await disassociateID(id);
			await refreshAffected([id], refreshMatches);
			setStatusText(statusLine, "");
		} catch (err) {
			setStatusText(statusLine, `Failed: ${err.message}`, true);
		} finally {
			btn.disabled = false;
		}
	});
	return btn;
}

function addChip(chipsEl, eid, refreshMatches, statusLine) {
	chipsEl.idKeys ??= new Set();
	const key = idKey(eid);
	if (chipsEl.idKeys.has(key)) return;
	chipsEl.idKeys.add(key);
	const chip = create("span", "chip");
	chip.append(idLink(eid.Domain, eid.ID), makeUngroupButton(eid, refreshMatches, statusLine));
	chipsEl.appendChild(chip);
}

// Sources of every ID in a card's group, including the card's own ID.
function groupDomains(match) {
	return new Set([match.ID, ...match.EquivalentIDs].map((eid) => eid.Domain));
}

// The server rejects a grouping when both groups already share a source.
function groupsConflict(a, b) {
	return [...a].some((domain) => b.has(domain));
}

// Dropping one result card onto another groups their IDs. The add-ID form
// remains as the keyboard-accessible alternative.
function makeCardDraggable(el, match, statusLine, refreshMatches) {
	el.draggable = true;
	el.classList.add("drop-card");
	el.title = "Drag onto another result to group their IDs";

	const canDrop = () => cardDrag && cardDrag.el !== el;
	const clearDropMarks = () => el.classList.remove("drop-target", "drop-blocked");

	el.addEventListener("dragstart", (e) => {
		// Let drags that start on child elements (text selections, links) behave normally.
		if (e.target !== el) return;
		cardDrag = { el, id: match.ID, domains: groupDomains(match) };
		const dragImage = el.querySelector("img.cover-thumb");
		if (dragImage) e.dataTransfer.setDragImage(dragImage, 24, 24);
		e.dataTransfer.items.add(`${match.ID.Domain}:${match.ID.ID}`, "text/plain");
		el.classList.add("dragging");
		e.dataTransfer.effectAllowed = "copy"; // "link" would fit better, but Chrome mishandles it
	});

	el.addEventListener("dragend", () => {
		cardDrag = null;
		el.classList.remove("dragging");
		for (const card of document.querySelectorAll(".drop-card.drop-target, .drop-card.drop-blocked")) {
			card.classList.remove("drop-target", "drop-blocked");
		}
	});

	el.addEventListener("dragenter", (e) => {
		e.dataTransfer.effectAllowed = "copy";
		if (canDrop()) e.preventDefault();
	});

	el.addEventListener("dragover", (e) => {
		if (!canDrop()) return;
		e.preventDefault();
		const blocked = groupsConflict(cardDrag.domains, groupDomains(match));
		e.dataTransfer.dropEffect = blocked ? "none" : "copy";
		el.classList.toggle("drop-blocked", blocked);
		el.classList.toggle("drop-target", !blocked);
	});

	el.addEventListener("dragleave", (e) => {
		if (!el.contains(e.relatedTarget)) clearDropMarks();
	});

	el.addEventListener("drop", async (e) => {
		if (!cardDrag || cardDrag.el === el) return;
		e.preventDefault();
		e.stopPropagation();
		const dragged = cardDrag;
		cardDrag = null;
		clearDropMarks();
		if (idKey(dragged.id) === idKey(match.ID)) return;
		if (groupsConflict(dragged.domains, groupDomains(match))) {
			setStatusText(statusLine, "Cannot group two IDs from the same source", true);
			return;
		}
		await groupIDs(match.ID, dragged.id, statusLine, refreshMatches);
		dragged.el.classList.remove("dragging");
	});
}

// Every distinct ID shown in a search, so the group form can suggest them.
function collectCandidateIDs(cards) {
	const seen = new Map();
	for (const card of cards) {
		for (const eid of [card.ID, ...card.EquivalentIDs]) {
			const key = idKey(eid);
			if (!seen.has(key)) seen.set(key, { Domain: eid.Domain, ID: eid.ID });
		}
	}
	return [...seen.values()];
}

// Groups the card's ID with a second ID entered by the user. The input offers
// IDs from the same search that are not yet grouped with this card, but any
// text can still be typed.
function makeGroupForm(match, chipsEl, refreshMatches, cardState) {
	const form = create("form", "group-form");
	const domainSelect = create("select");
	for (const domain of domains) {
		const option = create("option", "", domain);
		option.value = domain;
		domainSelect.appendChild(option);
	}
	// The server rejects grouping two IDs from the same source.
	const other = domains.find((d) => d !== match.ID.Domain);
	if (other) domainSelect.value = other;

	const idInput = create("input");
	idInput.type = "text";
	idInput.placeholder = "New ID";
	idInput.required = true;
	idInput.autocomplete = "off";
	const suggestWrap = create("div", "group-suggest");
	const suggestions = create("ul", "group-suggest-list");
	suggestions.id = `group-suggestions-${++groupSuggestionSeq}`;
	suggestions.setAttribute("role", "listbox");
	suggestions.hidden = true;
	setAttrs(idInput, { role: "combobox" });
	suggestWrap.append(idInput, suggestions);

	const candidateValues = () => {
		const selected = domainSelect.value;
		if (selected === match.ID.Domain) return [];
		const grouped = new Set(chipsEl.idKeys);
		grouped.add(idKey(match.ID));
		const query = idInput.value.trim().toLowerCase();
		return (cardState.candidateIDs ?? [])
			.filter((eid) => eid.Domain === selected && !grouped.has(idKey(eid)))
			.map((eid) => String(eid.ID))
			.filter((value) => value.toLowerCase().includes(query));
	};
	const closeSuggestions = () => {
		suggestions.hidden = true;
	};
	const setActive = (index) => {
		const items = [...suggestions.children];
		const next = (index + items.length) % items.length;
		items.forEach((item, i) => item.classList.toggle("active", i === next));
		items[next].scrollIntoView({ block: "nearest" });
	};
	const pickSuggestion = (value) => {
		idInput.value = value;
		closeSuggestions();
	};
	const renderSuggestions = () => {
		suggestions.replaceChildren(
			...candidateValues().map((value, index) => {
				const item = create("li", "", value);
				item.id = `${suggestions.id}-${index}`;
				item.setAttribute("role", "option");
				// mousedown keeps focus in the input so the list stays open until the click lands.
				item.addEventListener("mousedown", (e) => {
					e.preventDefault();
					pickSuggestion(value);
				});
				return item;
			}),
		);
		suggestions.hidden = suggestions.children.length === 0;
	};
	idInput.addEventListener("focus", renderSuggestions);
	idInput.addEventListener("input", renderSuggestions);
	idInput.addEventListener("blur", closeSuggestions);
	domainSelect.addEventListener("change", renderSuggestions);
	idInput.addEventListener("keydown", (e) => {
		if (suggestions.hidden) return;
		const items = [...suggestions.children];
		const activeIndex = items.findIndex((item) => item.classList.contains("active"));
		if (e.key === "ArrowDown") {
			e.preventDefault();
			setActive(activeIndex + 1);
		} else if (e.key === "ArrowUp") {
			e.preventDefault();
			setActive(activeIndex < 0 ? items.length - 1 : activeIndex - 1);
		} else if (e.key === "Enter" && activeIndex >= 0) {
			e.preventDefault();
			pickSuggestion(items[activeIndex].textContent);
		} else if (e.key === "Escape") {
			e.stopPropagation();
			closeSuggestions();
		}
	});

	const submit = create("button", "", "Group");
	submit.type = "submit";
	const status = createStatusLine("group-status", "span");
	form.append(domainSelect, suggestWrap, submit, status);
	form.addEventListener("submit", async (e) => {
		e.preventDefault();
		const newID = idInput.value.trim();
		if (!newID) return;
		submit.disabled = true;
		await groupIDs(match.ID, { Domain: domainSelect.value, ID: newID }, status, refreshMatches, {
			successText: "New ID added",
			onGrouped: () => {
				idInput.value = "";
			},
		});
		submit.disabled = false;
	});
	return form;
}

// ---------------------------------------------------------------------------
// Result cards
// ---------------------------------------------------------------------------

const linkedGroupLabel = (count) => `🔗 Linked group · ${plural(count, "ID")}`;

function renderMatch(match, cardState, searchHash, refreshMatches) {
	const url = sourceURL(match.ID.Domain, match.ID.ID);
	const el = create("article", "match-card");

	const idWrap = create("div", "match-id");
	idWrap.appendChild(idLink(match.ID.Domain, match.ID.ID));
	el.appendChild(idWrap);

	const thumb = makeCover(match.ImageURL, `${match.ID.ID} ${match.ID.Domain}`);
	if (url) {
		const imgA = create("a");
		imgA.href = url;
		imgA.draggable = false;
		imgA.appendChild(thumb);
		el.appendChild(imgA);
	} else {
		el.appendChild(thumb);
	}

	// One status line per card for grouping, ungrouping and drag feedback.
	const cardStatus = createStatusLine("group-status");
	const chips = create("div", "chips");
	for (const eid of match.EquivalentIDs) addChip(chips, eid, refreshMatches, cardStatus);
	idWrap.appendChild(makeUngroupButton(match.ID, refreshMatches, cardStatus));

	const compareBtn = create("button", "", "Compare stored");
	compareBtn.type = "button";
	const comparePanel = create("div", "compare-panel");
	compareBtn.addEventListener("click", () => compareStored(match.ID, searchHash, comparePanel));
	el.append(compareBtn, comparePanel);

	// Always render the same three kinds so cards line up identically, then any unexpected kinds.
	const byKind = new Map(match.Matches.map((m) => [m.Hash.Kind, m]));
	const extraKinds = [...byKind.keys()].filter((kind) => !DISPLAY_HASH_KINDS.includes(kind));
	const details = create("div", "match-details");
	for (const kind of [...DISPLAY_HASH_KINDS, ...extraKinds]) {
		const m = byKind.get(kind);
		const row = create("div", "match-row");
		row.append(
			create("span", "match-distance", `Distance: ${m ? m.Distance : "—"}`),
			" ",
			create("span", "match-kind", kind),
		);
		details.appendChild(row);
	}
	el.appendChild(details);

	// An empty chips container is invisible but must stay in the DOM so
	// chips added after grouping an ID are visible.
	el.append(chips, makeGroupForm(match, chips, refreshMatches, cardState), cardStatus);
	makeCardDraggable(el, match, cardStatus, refreshMatches);
	return el;
}

// Renders the cards whose IDs are already in one group inside a single labelled
// container so it is obvious at a glance that they are linked. Without this the
// two IDs show up as unrelated cards, each only hinting at the other via a chip.
function renderCluster(cards, cardState, searchHash, refreshMatches) {
	const cluster = create("div", "match-cluster");
	setAttrs(cluster, { role: "group" });
	const inner = create("div", "match-cluster-cards");
	inner.append(...cards.map((card) => renderMatch(card, cardState, searchHash, refreshMatches)));
	cluster.append(create("div", "match-cluster-label", linkedGroupLabel(cards.length)), inner);
	return cluster;
}

function createCardShell(titleText) {
	const card = create("section", "file-card");
	const refreshBtn = create("button", "refresh-btn", "↻");
	refreshBtn.title = "Refresh search";
	refreshBtn.disabled = true;
	const closeBtn = create("button", "close-btn", "×");
	const actions = create("div", "card-actions");
	actions.append(refreshBtn, closeBtn);
	const header = create("header");
	header.append(create("h2", "", titleText), actions);
	card.appendChild(header);
	return { card, refreshBtn, closeBtn };
}

function showEmptyState() {
	if (resultsEl.querySelector(".file-card, .empty-state")) return;
	resultsEl.appendChild(create("p", "empty-state", "No searches. Drop files to begin."));
}

function removeEmptyState() {
	resultsEl.querySelector(".empty-state")?.remove();
}

function updateClearButton() {
	clearAllBtn.hidden = !resultsEl.querySelector(".file-card");
}

function releasePreview(state) {
	if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
	state.previewUrl = null;
}

function discardState(state) {
	state.dismissed = true;
	resultStates.delete(state);
	openSearches.delete(state);
	releasePreview(state);
}

function removeCard(state) {
	discardState(state);
	state.card.remove();
	showEmptyState();
	updateClearButton();
}

// Drops every result, including cards still hashing. The active run is
// cancelled first so the files in flight cannot add their cards back.
function clearResults() {
	if (activeRun) cancelAll();
	for (const state of resultStates) discardState(state);
	resultsEl.replaceChildren();
	showEmptyState();
	updateClearButton();
}

// "N of M shown" is appended to the summary only while a source filter is active.
function summaryWithFilter(parts, visibleCount, totalCount, noun = "") {
	if (selectedDomains.size > 0) parts.push(`${visibleCount} of ${totalCount} ${noun}shown`);
	return parts.join(" · ");
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

// Fetches and parses JSON, reporting network and parse failures through
// `report`. Resolves null when the request failed or became stale.
async function requestJSON(url, { signal, isStale, report, parse = (response) => response.json() }) {
	let response;
	try {
		response = await fetch(url, { signal });
	} catch (err) {
		if (!isStale()) report(`Network error: ${err.message}`);
		return null;
	}
	if (isStale()) return null;
	let data;
	try {
		data = await parse(response);
	} catch (err) {
		if (!isStale()) report(`Invalid server response: ${err.message}`);
		return null;
	}
	return isStale() ? null : { response, data };
}

// ---------------------------------------------------------------------------
// Results from several hash kinds
// ---------------------------------------------------------------------------

// Collapses raw rows that refer to the same ID into one entry per ID. Callers
// decide how to order the result and what else to derive from entry.Matches.
function collapseRowsByID(results, { skipSelf = false } = {}) {
	const byKey = new Map();
	for (const r of results) {
		const key = idKey(r.ID);
		let entry = byKey.get(key);
		if (!entry) {
			entry = {
				ID: r.ID,
				ImageURL: r.ImageURL || "",
				EquivalentIDs: [],
				equivalentKeys: new Set(),
				Matches: [],
			};
			byKey.set(key, entry);
		}
		if (!entry.ImageURL) entry.ImageURL = r.ImageURL || "";
		entry.Matches.push(r);
		for (const eid of r.EquivalentIDs) {
			const eidKey = idKey(eid);
			// Duplicate cards do not need a chip linking an ID back to itself.
			if (skipSelf && eidKey === key) continue;
			if (entry.equivalentKeys.has(eidKey)) continue;
			entry.equivalentKeys.add(eidKey);
			entry.EquivalentIDs.push(eid);
		}
	}
	return [...byKey.values()];
}

const byDistanceThenDomain = (a, b) => a.Distance - b.Distance || a.ID.Domain.localeCompare(b.ID.Domain);

// Combines raw match rows that refer to the same ID into one card's worth of
// data, sorted by the closest match.
function combineResults(results) {
	// group by hash kind, sort each group by distance, keep first 10
	const groups = new Map(HASH_KINDS.map((kind) => [kind, []]));
	for (const r of results) {
		if (!groups.has(r.Hash.Kind)) groups.set(r.Hash.Kind, []);
		groups.get(r.Hash.Kind).push(r);
	}
	const limited = [];
	for (const rows of groups.values()) {
		rows.sort(byDistanceThenDomain);
		limited.push(...rows.slice(0, 10));
	}
	limited.sort(byDistanceThenDomain);

	// Combine results that refer to the same ID into a single card.
	const combined = collapseRowsByID(limited);
	for (const c of combined) {
		c.Matches.sort((a, b) => a.Distance - b.Distance || a.Hash.Kind.localeCompare(b.Hash.Kind));
		c.minDistance = c.Matches[0].Distance;
	}
	combined.sort(
		(a, b) => a.minDistance - b.minDistance || a.ID.Domain.localeCompare(b.ID.Domain) || a.ID.ID.localeCompare(b.ID.ID),
	);
	return combined;
}

// IDs that share one set of equivalent IDs belong to the same linked group.
function equivalenceKey(item) {
	const groupIDs = new Set(item.EquivalentIDs.map(idKey));
	groupIDs.add(idKey(item.ID));
	return [...groupIDs].sort().join("\n");
}

// Groups items that share equivalent IDs. The input must already be ordered;
// clusters and their contents keep that order.
function clusterByEquivalence(items) {
	const byKey = new Map();
	for (const item of items) {
		const key = equivalenceKey(item);
		if (!byKey.has(key)) byKey.set(key, []);
		byKey.get(key).push(item);
	}
	return [...byKey.values()];
}

// ---------------------------------------------------------------------------
// File search cards
// ---------------------------------------------------------------------------

function renderGrid(ctx) {
	const { state, grid, serverStatus, searchHash } = ctx;
	if (state.combined == null) return;
	const visible = state.combined.filter(cardMatchesFilter);
	grid.replaceChildren();
	// Report no matches if they are hidden by a filter
	if (visible.length === 0) {
		setStatusText(serverStatus, "No hashes found", true);
		return;
	}
	for (const cluster of clusterByEquivalence(visible)) {
		grid.appendChild(
			cluster.length > 1
				? renderCluster(cluster, state, searchHash, ctx.refresh)
				: renderMatch(cluster[0], state, searchHash, ctx.refresh),
		);
	}
	setStatusText(serverStatus, summaryWithFilter([state.summary], visible.length, state.combined.length));
}

// Re-runs the lookup so grouping changes made elsewhere show up here.
async function runMatchLookup(ctx) {
	const { state, signal, searchHash, serverStatus } = ctx;
	await domainsReady;
	const seq = ++ctx.requestSeq;

	const params = new URLSearchParams();
	if (includeAHash.checked) params.set("ahash", searchHash.ahash);
	params.set("dhash", searchHash.dhash);
	params.set("phash", searchHash.phash);
	params.set("max", String(currentMaxDistance()));
	params.set("exactOnly", String(exactOnlyInput.checked));
	params.set("images", "true");

	const reply = await requestJSON(`match_cover_hash?${params}`, {
		signal,
		isStale: () => state.dismissed || seq !== ctx.requestSeq,
		report: (message) => setStatusText(serverStatus, signal.aborted ? "Cancelled" : message, !signal.aborted),
	});
	if (!reply) return;
	const { response, data } = reply;
	if (!response.ok) {
		setStatusText(serverStatus, data.msg || response.statusText, true);
		return;
	}

	const results = data.results || [];
	state.combined = combineResults(results);
	state.candidateIDs = collectCandidateIDs(state.combined);
	state.summary = data.msg || plural(results.length, "match", "matches");
	renderGrid(ctx);
}

// Keeps the refresh button disabled while any lookup is still running.
async function refreshMatches(ctx) {
	const { state, refreshBtn } = ctx;
	ctx.pendingLookups++;
	refreshBtn.disabled = true;
	try {
		await runMatchLookup(ctx);
	} finally {
		ctx.pendingLookups--;
		if (ctx.pendingLookups === 0) refreshBtn.disabled = state.dismissed;
	}
}

// Downscales to a small preview so the full-size image can be released.
async function thumbnailUrl(source) {
	try {
		const bitmap = await createImageBitmap(source);
		const scale = Math.min(1, 480 / bitmap.height);
		const canvas = document.createElement("canvas");
		canvas.width = Math.round(bitmap.width * scale);
		canvas.height = Math.round(bitmap.height * scale);
		canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height);
		bitmap.close();
		const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/webp"));
		return blob ? URL.createObjectURL(blob) : null;
	} catch {
		return null;
	}
}

async function showPreview(state, searchImage, source) {
	const url = await thumbnailUrl(source);
	releasePreview(state);
	state.previewUrl = url;
	setCoverSource(searchImage, url || noImageURL);
	setTimeout(releasePreview, 1000, state);
}

async function processFile(file, pendingHash, signal) {
	removeEmptyState();

	const { card, refreshBtn, closeBtn } = createCardShell(file.name);
	const status = createStatusLine();
	setStatusText(status, "Computing hash...");
	card.appendChild(status);
	resultsEl.appendChild(card);

	const state = { card, dismissed: false, previewUrl: URL.createObjectURL(file) };
	resultStates.add(state);
	updateClearButton();
	closeBtn.addEventListener("click", () => removeCard(state));

	const el = create("article", "match-card");
	const searchImage = makeCover(state.previewUrl, file.name);
	searchImage.draggable = true;
	el.appendChild(searchImage);

	const result = await pendingHash;
	try {
		if (!result.hash?.image) {
			showPreview(state, searchImage, file);
			if (result.error) throw result.error;
		} else {
			showPreview(state, searchImage, new Blob([result.hash.image]));
			result.hash.image = null;
		}
	} catch (err) {
		if (state.dismissed) {
			if (signal.aborted) setStatusText(status, "Cancelled");
			return;
		}
		setStatusText(status, `Error: ${err.message}`, true);
		return;
	}

	if (state.dismissed) return;

	if (signal.aborted) {
		setStatusText(status, "Cancelled");
		return;
	}

	if (result.hash.error) {
		setStatusText(status, result.hash.error, true);
		return;
	}

	setStatusText(status, "");
	const searchHash = {
		ahash: result.hash.ahash,
		dhash: result.hash.dhash,
		phash: result.hash.phash,
	};

	const entryName = String(result.hash.entry ?? "").split("/").pop();
	const serverStatus = createStatusLine("server-status");
	const hashesEl = create("p", "hashes");
	DISPLAY_HASH_KINDS.forEach((kind, i) => {
		if (i > 0) hashesEl.appendChild(create("br"));
		hashesEl.append(`${kind} ${searchHash[kind]}`);
	});
	const metaContainer = create("div", "meta-info");
	metaContainer.append(
		create("p", "meta", `${entryName} — ${result.hash.format} — ${result.hash.width}×${result.hash.height}`),
		serverStatus,
		hashesEl,
	);
	el.appendChild(metaContainer);
	card.appendChild(el);

	const grid = create("div", "match-grid");
	card.appendChild(grid);

	const ctx = {
		state,
		signal,
		searchHash,
		grid,
		serverStatus,
		refreshBtn,
		requestSeq: 0,
		pendingLookups: 0,
	};
	ctx.refresh = () => refreshMatches(ctx);
	refreshBtn.addEventListener("click", () => ctx.refresh());

	state.refresh = ctx.refresh;
	state.applyFilter = () => renderGrid(ctx);
	openSearches.add(state);
	await ctx.refresh();
}

// ---------------------------------------------------------------------------
// Duplicate groups
// ---------------------------------------------------------------------------

// Issue details are not returned by the API yet. Read the likely field names so
// the collapsed summary and the expanded card can show them once they exist.
function readIssueInfo(entry) {
	return entry.IssueInfo ?? entry.issueInfo ?? entry.issue;
}

function duplicateIssueInfoText(entry) {
	const value = readIssueInfo(entry);
	if (value == null) return "";
	if (typeof value === "string") return value.trim();
	if (Array.isArray(value)) return value.filter(Boolean).join(" · ");
	return String(value);
}

function makeIssueInfo(entry, tag = "div", className = "issue-info") {
	const node = create(tag, className);
	const text = duplicateIssueInfoText(entry);
	if (text) node.textContent = text;
	else node.dataset.placeholder = "Issue information";
	return node;
}

// get_duplicates returns every hash row for every ID in the group. Collapse the
// rows once, then order the entries so every view of the group agrees.
function normalizeDuplicateGroup(group) {
	const entries = collapseRowsByID(group, { skipSelf: true });
	for (const entry of entries) {
		entry.hashes = new Map();
		for (const r of entry.Matches) {
			// Issue details are not returned yet; keep the first one seen so the
			// collapsed summary can show them once the API starts sending them.
			entry.IssueInfo ??= readIssueInfo(r);
			entry.hashes.set(r.Hash.Kind, r.Hash.Hash);
		}
		entry.EquivalentIDs.sort(compareIDs);
	}
	return entries.sort((a, b) => compareIDs(a.ID, b.ID));
}

// An ID is already linked only when the server reports an equivalent ID for it.
// Two IDs sharing a hash are duplicates to review, not a link; the association
// lives in EquivalentIDs and nowhere else.
function duplicateEntryIsLinked(entry) {
	return entry.EquivalentIDs.length > 0;
}

// Hash kinds used to line up duplicate IDs with their counterparts on other
// sources. phash is compared first, dhash breaks ties, and ahash is only used
// when the user has explicitly asked for it.
function duplicateCompareKinds() {
	return includeAHash.checked ? HASH_KINDS : HASH_KINDS.slice(0, 2);
}

function duplicateHash(entry, kind) {
	const value = entry.hashes.get(kind);
	if (value == null) return null;
	const cache = (entry.parsedHashes ??= new Map());
	if (!cache.has(kind)) cache.set(kind, parseHash(value, 10));
	return cache.get(kind);
}

// One hamming distance per comparison kind, in preference order. A kind is
// null when either ID has no hash of that kind.
function duplicateHashDistances(a, b, kinds) {
	return kinds.map((kind) => {
		const left = duplicateHash(a, kind);
		const right = duplicateHash(b, kind);
		return left == null || right == null ? null : popcount(left.n ^ right.n);
	});
}

// Compare distance vectors lexicographically so phash wins over dhash and
// dhash wins over ahash when the stronger hash cannot tell two IDs apart.
function compareDuplicateDistances(a, b) {
	for (let i = 0; i < a.length; i++) {
		if (a[i] == null || b[i] == null) continue;
		if (a[i] !== b[i]) return a[i] - b[i];
	}
	return 0;
}

// Places each ID in a row with the closest IDs from the other sources. Rows
// only ever hold one ID per source because two IDs from the same source cannot
// be associated with each other. The source with the most IDs seeds the rows,
// then each remaining ID is matched to its best available row, so the same
// comic from different sources ends up side by side.
function groupDuplicateIDRows(entries) {
	const kinds = duplicateCompareKinds();
	const domains = domainsOf(entries);
	if (domains.length === 0) return { domains, rows: [] };

	const byDomain = new Map(domains.map((domain) => [domain, entries.filter((entry) => entry.ID.Domain === domain)]));
	const anchorDomain = domains.reduce((best, domain) =>
		byDomain.get(domain).length > byDomain.get(best).length ? domain : best,
	);
	const rows = byDomain.get(anchorDomain).map((entry) => ({ entries: new Map([[anchorDomain, entry]]) }));

	for (const domain of domains) {
		if (domain === anchorDomain) continue;
		for (const entry of byDomain.get(domain)) {
			let bestRow = null;
			let bestDistance = null;
			for (const row of rows) {
				if (row.entries.has(domain)) continue;
				const rowDistance = [...row.entries.values()]
					.map((other) => duplicateHashDistances(entry, other, kinds))
					.reduce((best, distance) => (compareDuplicateDistances(distance, best) < 0 ? distance : best));
				if (!bestDistance || compareDuplicateDistances(rowDistance, bestDistance) < 0) {
					bestRow = row;
					bestDistance = rowDistance;
				}
			}
			if (bestRow) bestRow.entries.set(domain, entry);
			else rows.push({ entries: new Map([[domain, entry]]) });
		}
	}

	// Entries are already ordered; sort rows by their first entry so each
	// source's IDs still read top to bottom in numeric order.
	const firstEntry = (row) => domains.map((domain) => row.entries.get(domain)).find(Boolean);
	rows.sort((a, b) => compareIDs(firstEntry(a)?.ID, firstEntry(b)?.ID));
	return { domains, rows };
}

function createDuplicateCard(session, title) {
	removeEmptyState();
	const { card, refreshBtn, closeBtn } = createCardShell(title);
	const state = { card, dismissed: false, previewUrl: null };
	const ctx = { session, state, refreshBtn };
	ctx.refresh = () => refreshDuplicates(session);

	closeBtn.addEventListener("click", () => dismissDuplicateCard(ctx));
	refreshBtn.addEventListener("click", () => ctx.refresh());

	resultStates.add(state);
	session.cards.add(ctx);
	updateClearButton();
	return ctx;
}

function dismissDuplicateCard(ctx) {
	ctx.session.cards.delete(ctx);
	removeCard(ctx.state);
}

function setCompareState(card, button, index) {
	const selected = index >= 0;
	card.classList.toggle("compare-selected", selected);
	button.textContent = selected ? `Selected ${index === 0 ? "A" : "B"}` : "Compare";
	button.classList.toggle("compare-selected", selected);
}

// A compact card for one ID in a duplicate group. It keeps hash values visible
// and reserves a spot for issue details, unlike the cards used for file searches.
function renderDuplicateIDCard(ctx, entry) {
	const { state } = ctx;
	const key = idKey(entry.ID);
	const el = create("article", "duplicate-id-card");
	const cardStatus = createStatusLine("group-status");

	const thumb = makeCover(entry.ImageURL, `${entry.ID.ID} ${entry.ID.Domain}`);
	const url = sourceURL(entry.ID.Domain, entry.ID.ID);
	if (url) {
		const link = create("a", "duplicate-id-cover");
		link.href = url;
		link.target = "_blank";
		link.rel = "noopener noreferrer";
		link.appendChild(thumb);
		el.appendChild(link);
	} else {
		el.appendChild(thumb);
	}

	const body = create("div", "duplicate-id-body");
	const idWrap = create("div", "match-id");
	idWrap.appendChild(idLink(entry.ID.Domain, entry.ID.ID));
	// The issue info is reserved for details that will be added later.
	body.append(idWrap, makeIssueInfo(entry));

	const hashes = create("dl", "duplicate-hashes");
	for (const kind of DISPLAY_HASH_KINDS) {
		const value = entry.hashes.get(kind);
		const hash = create("dd", "", formatHash(value));
		if (value != null) hash.title = `decimal ${value}`;
		const row = create("div", "duplicate-hash");
		row.append(create("dt", "", kind), hash);
		hashes.appendChild(row);
	}
	body.appendChild(hashes);

	const actions = create("div", "duplicate-actions");
	const compareBtn = create("button", "compare-toggle");
	compareBtn.type = "button";
	compareBtn.title = "Select this ID to compare its hashes with another ID";
	setCompareState(el, compareBtn, state.compareSelection.indexOf(key));
	compareBtn.addEventListener("click", () => toggleDuplicateCompare(ctx, entry));
	actions.appendChild(compareBtn);
	if (entry.EquivalentIDs.length > 0) actions.appendChild(makeUngroupButton(entry.ID, ctx.refresh, cardStatus));
	body.appendChild(actions);

	if (entry.EquivalentIDs.length > 0) {
		const linkedChips = create("div", "chips");
		for (const eid of entry.EquivalentIDs) addChip(linkedChips, eid, ctx.refresh, cardStatus);
		const linked = create("div", "duplicate-linked");
		linked.append(create("span", "duplicate-linked-label", "Linked IDs"), linkedChips);
		body.appendChild(linked);
	}

	// Keep a keyboard-accessible alternative to dragging, but collapsed so the
	// cards stay compact when it is not needed.
	const manual = create("details", "duplicate-manual");
	// makeGroupForm only needs this set to avoid suggesting IDs already linked.
	const manualChips = create("div", "chips");
	manualChips.idKeys = new Set(entry.EquivalentIDs.map(idKey));
	manual.append(create("summary", "", "Add ID manually"), makeGroupForm(entry, manualChips, ctx.refresh, state));
	body.append(manual, cardStatus);
	el.appendChild(body);

	state.compareButtons.set(key, { card: el, button: compareBtn });
	makeCardDraggable(el, entry, cardStatus, ctx.refresh);
	return el;
}

function toggleDuplicateCompare(ctx, entry) {
	const selection = ctx.state.compareSelection;
	const key = idKey(entry.ID);
	const index = selection.indexOf(key);
	if (index >= 0) {
		selection.splice(index, 1);
	} else {
		selection.push(key);
		// Only two IDs can be compared at a time; the oldest selection drops out.
		if (selection.length > 2) selection.shift();
	}
	updateDuplicateCompareSelection(ctx);
}

function updateDuplicateCompareSelection(ctx) {
	const { compareSelection, compareButtons } = ctx.state;
	for (const [key, { card, button }] of compareButtons) {
		setCompareState(card, button, compareSelection.indexOf(key));
	}
	renderDuplicateCompare(ctx);
}

// Shows the two selected IDs' hashes side by side, with differing bits marked.
function renderDuplicateCompare(ctx) {
	const { state, comparePanel: panel } = ctx;
	const selected = state.compareSelection
		.map((key) => state.entries.find((entry) => idKey(entry.ID) === key))
		.filter(Boolean);
	// A filter may have hidden a selected ID since the selection was made.
	state.compareSelection = selected.map((entry) => idKey(entry.ID));
	panel.replaceChildren();
	panel.hidden = selected.length === 0;
	if (selected.length === 0) return;

	const clear = create("button", "duplicate-compare-clear", "Clear");
	clear.type = "button";
	clear.addEventListener("click", () => {
		state.compareSelection = [];
		updateDuplicateCompareSelection(ctx);
	});
	const head = create("div", "duplicate-compare-head");
	head.append(create("strong", "", "Hash comparison"), clear);

	if (selected.length < 2) {
		const hint = create("p", "duplicate-compare-hint", `Select a second ID to compare with A: ${idLabel(selected[0].ID)}.`);
		panel.append(head, hint);
		return;
	}
	const [a, b] = selected;

	const legend = create("div", "duplicate-compare-legend");
	legend.append("A: ", idLink(a.ID.Domain, a.ID.ID), " · B: ", idLink(b.ID.Domain, b.ID.ID));

	const list = create("div", "hash-compares");
	for (const kind of DISPLAY_HASH_KINDS) {
		if (a.hashes.get(kind) == null && b.hashes.get(kind) == null) continue;
		const parsedA = duplicateHash(a, kind);
		const parsedB = duplicateHash(b, kind);
		const both = parsedA && parsedB;
		list.appendChild(
			makeHashCompare(
				kind,
				both ? "A over B · highlighted bits differ" : "missing hash",
				null,
				both ? renderBitCompare(parsedA, parsedB) : null,
			),
		);
	}
	panel.append(head, legend, list);
}

// One header cell per source, in a grid with the same number of cells as every
// row below it, so the headers stay aligned with their columns.
function renderDuplicateHeader(domains, entries) {
	const row = create("div", "duplicate-id-row duplicate-id-head-row");
	for (const domain of domains) {
		const cell = create("div", "duplicate-id-cell duplicate-id-column-head");
		cell.dataset.domain = domain;
		if (domain) cell.append(makeDomainIcon(domain), domain);
		else cell.textContent = "Unknown source";
		const count = entries.filter((entry) => entry.ID.Domain === domain).length;
		cell.appendChild(create("span", "duplicate-id-column-count", plural(count, "ID")));
		row.appendChild(cell);
	}
	return row;
}

// The collapsed summary for one linked duplicate issue. It always lists the
// issue IDs and adds issue details when the API starts returning them.
function renderDuplicateIssueSummary(entries) {
	const summary = create("summary", "duplicate-issue-summary");

	const marker = create("span", "duplicate-issue-summary-marker");
	const heading = create("span", "duplicate-issue-summary-heading");
	// Same label as renderCluster so a linked group reads the same everywhere.
	heading.append(marker, create("span", "match-cluster-label", linkedGroupLabel(entries.length)));

	const ids = create("span", "duplicate-issue-summary-ids");
	for (const entry of entries) {
		const line = create("span", "duplicate-issue-summary-id");
		line.appendChild(idLink(entry.ID.Domain, entry.ID.ID));
		if (duplicateIssueInfoText(entry)) {
			line.appendChild(makeIssueInfo(entry, "span", "issue-info issue-info-inline"));
		}
		ids.appendChild(line);
	}
	summary.append(heading, ids);
	return summary;
}

// One visual row of duplicate IDs: every source gets a cell, and sources with
// no ID for this row get an empty placeholder so later columns stay put. Used
// by both pending rows and already-linked groups.
function renderDuplicateCells(ctx, domains, byDomain) {
	const row = create("div", "duplicate-id-row");
	for (const domain of domains) {
		const cell = create("div", "duplicate-id-cell");
		cell.dataset.domain = domain;
		const entry = byDomain.get(domain);
		if (entry) {
			cell.appendChild(renderDuplicateIDCard(ctx, entry));
		} else {
			cell.classList.add("duplicate-id-cell-empty");
		}
		row.appendChild(cell);
	}
	return row;
}

// IDs the server already associated are done, so they render as one collapsed
// group just like renderCluster does for matching covers: the summary names the
// linked IDs and any issue details, and expanding it shows the full cards.
function renderDuplicateCluster(ctx, cluster, domains) {
	const el = create("details", "duplicate-issue duplicate-issue-linked");
	const key = equivalenceKey(cluster[0]);
	const expanded = ctx.state.expandedClusters;
	el.open = expanded.has(key);
	el.addEventListener("toggle", () => {
		if (el.open) expanded.add(key);
		else expanded.delete(key);
	});
	const byDomain = new Map(cluster.map((entry) => [entry.ID.Domain, entry]));
	el.append(renderDuplicateIssueSummary(cluster), renderDuplicateCells(ctx, domains, byDomain));
	return el;
}

// Re-renders one duplicate group after a filter or compare-selection change.
function renderDuplicateGroupBody(ctx) {
	const { state, grid, serverStatus } = ctx;
	const visible = state.entries.filter(cardMatchesFilter);
	const visibleKeys = new Set(visible.map((entry) => idKey(entry.ID)));
	state.compareSelection = state.compareSelection.filter((key) => visibleKeys.has(key));
	grid.replaceChildren();
	state.compareButtons = new Map();
	if (visible.length === 0) {
		setStatusText(serverStatus, "No duplicate hashes match the current filters", true);
		renderDuplicateCompare(ctx);
		return;
	}
	// IDs the server already associated need no review, so they drop to the
	// bottom as collapsed linked groups. The remaining IDs keep the row/column
	// layout, with one row per comic and one cell per source.
	const pending = visible.filter((entry) => !duplicateEntryIsLinked(entry));
	const clusters = clusterByEquivalence(visible.filter(duplicateEntryIsLinked));

	const { domains: pendingDomains, rows } = groupDuplicateIDRows(pending);
	const headerDomains = pendingDomains.length > 0 ? pendingDomains : domainsOf(visible);
	if (headerDomains.length > 0) grid.appendChild(renderDuplicateHeader(headerDomains, pending));
	for (const row of rows) grid.appendChild(renderDuplicateCells(ctx, headerDomains, row.entries));
	for (const cluster of clusters) grid.appendChild(renderDuplicateCluster(ctx, cluster, headerDomains));

	const parts = [state.summary];
	if (rows.length) parts.push(plural(rows.length, "row"));
	if (clusters.length) parts.push(`${clusters.reduce((total, cluster) => total + cluster.length, 0)} already linked`);
	setStatusText(serverStatus, summaryWithFilter(parts, visible.length, state.entries.length, "IDs "));
	updateDuplicateCompareSelection(ctx);
}

function addDuplicateGroup(session, index, entries) {
	scheduler.yield();
	const ctx = createDuplicateCard(session, `Duplicates ${index + 1}`);
	const { state } = ctx;

	ctx.serverStatus = createStatusLine("server-status");
	ctx.grid = create("div", "duplicate-id-grid");
	ctx.comparePanel = create("div", "duplicate-compare");
	ctx.comparePanel.hidden = true;
	setAttrs(ctx.comparePanel, { role: "region" });

	state.card.append(ctx.serverStatus, ctx.grid, ctx.comparePanel);
	resultsEl.appendChild(state.card);

	state.entries = entries;
	state.compareSelection = [];
	state.compareButtons = new Map();
	state.expandedClusters = new Set();
	state.candidateIDs = collectCandidateIDs(entries);
	// Count IDs, not the three hash rows each ID contributes to the response.
	state.summary = plural(entries.length, "duplicate");
	state.refresh = ctx.refresh;
	state.applyFilter = () => renderDuplicateGroupBody(ctx);
	openSearches.add(state);
	renderDuplicateGroupBody(ctx);
	return ctx;
}

// Shows progress/errors in a card of its own, which is replaced by the group cards on success.
function showDuplicatesStatus(session, text, isError = false) {
	let ctx = session.statusCtx;
	if (!ctx || ctx.state.dismissed) {
		ctx = createDuplicateCard(session, "Duplicates");
		ctx.status = createStatusLine();
		ctx.state.card.appendChild(ctx.status);
		resultsEl.prepend(ctx.state.card);
		session.statusCtx = ctx;
	}
	setStatusText(ctx.status, text, isError);
}

async function runDuplicatesLookup(session) {
	const { signal } = session;
	await domainsReady;
	const seq = ++session.requestSeq;
	showDuplicatesStatus(session, "Searching for duplicates...");

	const reply = await requestJSON("get_duplicates?images=true", {
		signal,
		isStale: () => seq !== session.requestSeq || session.statusCtx.state.dismissed,
		report: (message) => showDuplicatesStatus(session, signal.aborted ? "Cancelled" : message, !signal.aborted),
		parse: (response) => response.text().then(parseHashJSON),
	});
	if (!reply) return;
	const { response, data } = reply;
	if (!response.ok) {
		showDuplicatesStatus(session, data.msg || response.statusText, true);
		return;
	}

	// `results` is a list of groups, each group being a list of results
	const groups = (data.results || []).filter(
		(group) => includeAHash.checked || group.some((m) => m.Hash.Kind !== "ahash"),
	);
	const previous = [...session.cards];
	if (groups.length === 0) {
		for (const ctx of previous) {
			if (ctx !== session.statusCtx) dismissDuplicateCard(ctx);
		}
		showDuplicatesStatus(session, data.msg || "No duplicates found");
		return;
	}
	// De-prioritize duplicate groups whose IDs are already associated; they do
	// not need a grouping action and should appear after actionable groups.
	const fullyLinked = (entries) => entries.length > 0 && entries.every(duplicateEntryIsLinked);
	const prepared = groups
		.map(normalizeDuplicateGroup)
		.sort((a, b) => Number(fullyLinked(a)) - Number(fullyLinked(b)));
	for (let index = 0; index < Math.min(100, prepared.length); index++) {
		addDuplicateGroup(session, index, prepared[index]);
	}
	// Replace the status card and any cards from a previous lookup
	for (const ctx of previous) dismissDuplicateCard(ctx);
}

function refreshDuplicates(session) {
	// Refreshes requested in the same tick (e.g. one per open card) share one lookup
	session.refreshing ??= Promise.resolve().then(() => {
		session.refreshing = null;
		return trackDuplicatesLookup(session);
	});
	return session.refreshing;
}

// Keeps the refresh buttons disabled while any lookup is still running.
async function trackDuplicatesLookup(session) {
	const setDisabled = (disabled) => {
		for (const ctx of session.cards) ctx.refreshBtn.disabled = disabled || ctx.state.dismissed;
	};
	session.pendingLookups++;
	setDisabled(true);
	try {
		await runDuplicatesLookup(session);
	} finally {
		session.pendingLookups--;
		if (session.pendingLookups === 0) setDisabled(false);
	}
}

// Queries /get_duplicates once and shows one card per duplicate group.
// Duplicate groups use compact ID cards with inline hash comparison.
function findDuplicates() {
	const session = {
		signal: runController.signal,
		requestSeq: 0,
		pendingLookups: 0,
		refreshing: null,
		cards: new Set(),
		statusCtx: null,
	};
	refreshDuplicates(session).catch((err) => console.error(err));
}

// ---------------------------------------------------------------------------
// Collecting dropped files
// ---------------------------------------------------------------------------

// Must run synchronously inside the drop event; entries become invalid after it.
function dropItems(dataTransfer) {
	const items = Array.from(dataTransfer.items || [])
		.filter((item) => item.kind === "file")
		.map((item) => item.getAsFile() || item.webkitGetAsEntry())
		.filter(Boolean);
	return items.length > 0 ? items : Array.from(dataTransfer.files || []);
}

async function walkEntry(entry, signal, found, nested) {
	if (signal.aborted) throw abortError();
	if (nested && (entry.name.startsWith(".") || entry.name === "__MACOSX")) return;
	if (entry.isFile) {
		if (
			nested &&
			entry.size > 1024 * 1024 * 5 && // If this is recursive and over 5 MB
			!supportedFileName.test(entry.name) // Skip the file if the extension isn't a known extension
		) {
			return;
		}
		found.push(await new Promise((resolve, reject) => entry.file(resolve, reject)));
		return;
	}
	if (entry.isDirectory) {
		const reader = entry.createReader();
		const readBatch = () => new Promise((resolve, reject) => reader.readEntries(resolve, reject));
		for (let batch = await readBatch(); batch.length > 0; batch = await readBatch()) {
			for (const child of batch) await walkEntry(child, signal, found, true);
		}
	}
}

async function collectFiles(items, signal) {
	const found = [];
	for (const item of items) {
		if (item instanceof File) found.push(item);
		else await walkEntry(item, signal, found, false);
	}
	found.sort((a, b) =>
		(a.webkitRelativePath || a.name).localeCompare(b.webkitRelativePath || b.name, undefined, { numeric: true }),
	);
	return found;
}

// ---------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------

function enqueue(items) {
	if (activeRun) addToRun(activeRun, items);
	else runBatch(items);
}

function cancelAll() {
	if (!activeRun) return;
	const run = activeRun;
	runController.abort();
	runController = new AbortController();
	finishRun(run);
}

// todo: validate this handles adding to an in-process run
async function runBatch(items) {
	const run = {
		signal: runController.signal,
		files: [],
		queued: [],
		batchInFlight: null,
		hashed: 0,
		hashCount: 0,
		hashMsTotal: 0,
		done: 0,
		workers: [],
		nextWorker: 0,
		ready: null,
		finished: false,
	};
	activeRun = run;
	cancelBtn.hidden = false;
	run.workers = Array.from({ length: hashWorkerCount }, () => startHashWorker());
	run.ready = Promise.all(run.workers.map((w) => w.ready));
	run.ready.catch((err) => {
		if (!run.signal.aborted) setStatusText(statusEl, `Failed to load hasher: ${err.message}`, { error: true });
	});

	setStatusText(statusEl, "Scanning...");
	const batchStart = performance.now();
	try {
		appendFiles(run, await collectFiles(items, run.signal));
		if (run.files.length === 0) {
			setStatusText(statusEl, "No supported files found");
			return;
		}
		while (run.batchInFlight && !run.signal.aborted) {
			await run.batchInFlight;
		}
		const seconds = ((performance.now() - batchStart) / 1000).toFixed(1);
		const avgHash = run.hashCount ? (run.hashMsTotal / run.hashCount).toFixed(0) : "–";
		const lastRun = `Last run: ${seconds} s, ${run.done} of ${run.files.length} files, avg hash ${avgHash} ms`;
		setStatusText(statusEl, run.signal.aborted ? `Cancelled. ${lastRun}` : lastRun);
		if (!resultsEl.querySelector(".file-card")) showEmptyState();
	} catch (err) {
		const aborted = err.name === "AbortError";
		setStatusText(statusEl, aborted ? "Cancelled" : `Failed to read: ${err.message}`, { error: !aborted });
	} finally {
		finishRun(run);
	}
}

async function addToRun(run, items) {
	let files;
	try {
		files = await collectFiles(items, run.signal);
	} catch {
		return;
	}
	if (run.signal.aborted || files.length === 0) return;
	if (run.finished) enqueue(files);
	else appendFiles(run, files);
}

function appendFiles(run, files) {
	for (const file of files) {
		run.files.push(file);
		run.queued.push(file);
	}
	updateStatus(run);
	scheduleBatch(run);
}

// A batch is hashBatchSize files, each hashed and looked up as one operation.
// The next batch starts once every file in the current batch has finished.
function scheduleBatch(run) {
	if (run.finished || run.batchInFlight) return;
	const batch = run.queued.splice(0, hashBatchSize);
	if (batch.length === 0) return;
	run.batchInFlight = Promise.all(batch.map((file) => runFile(run, file))).then(() => {
		run.batchInFlight = null;
		scheduleBatch(run);
	});
}

function runFile(run, file) {
	const hash = dispatchHash(run, file).then((result) => {
		run.hashed++;
		if (!result.error) {
			run.hashCount++;
			run.hashMsTotal += result.hashMs;
		}
		updateStatus(run);
		return result;
	});
	return processFile(file, hash, run.signal)
		.catch((err) => console.error(err))
		.finally(() => {
			run.done++;
			updateStatus(run);
		});
}

function updateStatus(run) {
	if (run.finished) return;
	setStatusText(statusEl, `Hashed ${run.hashed} of ${run.files.length}`);
}

function finishRun(run) {
	if (run.finished) return;
	run.finished = true;
	run.queued = [];
	for (const { worker } of run.workers) stopHashWorker(worker);
	if (activeRun === run) activeRun = null;
	cancelBtn.hidden = true;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

function init() {
	fileInput.disabled = false;

	dropZone.addEventListener("dragover", (e) => {
		e.preventDefault();
		dropZone.classList.add("dragover");
	});
	dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
	dropZone.addEventListener("drop", (e) => {
		e.preventDefault();
		dropZone.classList.remove("dragover");
	});

	fileInput.addEventListener("change", (e) => {
		enqueue(Array.from(e.target.files));
		fileInput.value = "";
	});

	checkDuplicates.addEventListener("click", findDuplicates);
	cancelBtn.addEventListener("click", cancelAll);
	clearAllBtn.addEventListener("click", clearResults);
	document.addEventListener("keydown", (e) => {
		if (e.key === "Escape") cancelAll();
	});

	document.addEventListener("dragover", (e) => {
		if (!hasFiles(e)) return;
		e.preventDefault();
		document.body.classList.add("dragging");
	});
	document.addEventListener("dragleave", (e) => {
		// only remove when leaving window
		if (hasFiles(e) && e.clientX === 0 && e.clientY === 0) document.body.classList.remove("dragging");
	});
	document.addEventListener("drop", (e) => {
		if (!hasFiles(e)) return;
		e.preventDefault();
		document.body.classList.remove("dragging");
		enqueue(dropItems(e.dataTransfer));
	});
}

init();