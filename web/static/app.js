const statusEl = document.getElementById("status");
const processStatusEl = document.getElementById("process-status");
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
const version = document.querySelector('meta[name="static-version"]').content;
const noImageURL = `static/no-image.svg?v=${version}`;
const checkURL = `static/check.svg?v=${version}`;
const hashWorkerURL = `static/hash-worker.js?v=${version}`;

let domains = [];
const selectedDomains = new Set();

// Each run starts its own hash workers and terminates them when the run ends.
const hashWorkerCount = 4;
const hashRequests = new Map();
let nextHashId = 1;
let activeRun = null;

function startHashWorker() {
	const worker = new Worker(hashWorkerURL);
	const ready = new Promise((resolveReady, rejectReady) => {
		worker.onmessage = (e) => {
			const { id, ok, result, error } = e.data;
			if (id === 0) {
				if (ok) resolveReady();
				else rejectReady(new Error(error));
				return;
			}
			const request = hashRequests.get(id);
			hashRequests.delete(id);
			if (ok) request.resolve(result);
			else request.reject(new Error(error));
		};
		worker.onerror = (e) => rejectReady(new Error(e.message || "hasher worker failed to load"));
	});
	return { worker, ready };
}

function stopHashWorker(worker) {
	worker.terminate();
	for (const [id, request] of hashRequests) {
		if (request.worker !== worker) continue;
		hashRequests.delete(id);
		request.reject(new DOMException("Cancelled", "AbortError"));
	}
}
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

// Each search bit sits directly above the stored bit. Differing columns are marked.
function renderBitCompare(search, stored) {
	const bytes = document.createElement("div");
	bytes.className = "bit-bytes";
	if (!search.bits || !stored.bits) {
		bytes.textContent = "—";
		return bytes;
	}
	const length = Math.max(search.bits.length, stored.bits.length);
	bytes.setAttribute("aria-label", `search ${search.bits}, stored ${stored.bits}`);
	for (let start = 0; start < length; start += 8) {
		const byte = document.createElement("span");
		byte.className = "bit-byte";
		byte.setAttribute("aria-hidden", "true");
		for (let i = start; i < Math.min(start + 8, length); i++) {
			const pair = document.createElement("span");
			pair.className = "bit-pair";
			if (search.bits && stored.bits && search.bits[i] !== stored.bits[i]) {
				pair.classList.add("bit-diff");
			}
			pair.append(search.bits[i], document.createElement("br"), stored.bits[i]);
			byte.appendChild(pair);
		}
		bytes.appendChild(byte);
	}
	return bytes;
}

async function compareStored(id, searchHash, panel) {
	panel.classList.remove("error");
	try {
		const params = new URLSearchParams({ domain: id.Domain, id: id.ID });
		const response = await fetch(`get_cover_hash?${params.toString()}`);
		const jsonText = await response.text();
		const fixedText = jsonText.replace(/([^\w"])([0-9]{16,})([^\w"])/g, '$1"$2"$3');
		const data = JSON.parse(fixedText);
		if (!response.ok) throw new Error(data.msg || response.statusText);
		const results = data.results || [];
		if (results.length === 0) {
			panel.textContent = "No hashes";
			return;
		}
		const list = document.createElement("div");
		list.className = "hash-compares";
		for (const r of results) {
			const kind = r.Kind;
			const stored = parseHash(r.Hash, 10);
			const search = parseHash(searchHash[kind], 16);
			const block = document.createElement("div");
			block.className = "hash-compare";

			const head = document.createElement("div");
			head.className = "hash-compare-head";
			const kindEl = document.createElement("span");
			kindEl.className = "hash-kind";
			kindEl.textContent = kind || "—";
			const hint = document.createElement("span");
			hint.className = "bit-hint";
			hint.textContent = "search over stored";
			const distEl = document.createElement("span");
			distEl.className = "hash-distance";
			if (search && stored) {
				distEl.textContent = `distance ${popcount(search.n ^ stored.n)}`;
			} else {
				distEl.textContent = "distance —";
			}
			head.append(kindEl, hint, distEl);
			block.append(head, renderBitCompare(search, stored));
			list.appendChild(block);
		}
		panel.replaceChildren(list);
	} catch (err) {
		panel.textContent = `Error: ${err.message}`;
		panel.classList.add("error");
	}
}
async function hashOn(run, worker, file) {
	await run.ready;
	if (run.finished) throw new DOMException("Cancelled", "AbortError");
	const id = nextHashId++;
	return new Promise((resolve, reject) => {
		hashRequests.set(id, { resolve, reject, worker });
		worker.postMessage({ id, file });
	});
}

function dispatchHash(run, file) {
	const { worker } = run.workers[run.nextWorker++ % run.workers.length];
	const hashStart = performance.now();
	return hashOn(run, worker, file).then(
		(hash) => ({ hash, hashMs: performance.now() - hashStart }),
		(error) => ({ error }),
	);
}

function init() {
	fileInput.disabled = false;

	dropZone.addEventListener("dragover", (e) => {
		e.preventDefault();
		dropZone.classList.add("dragover");
	});

	dropZone.addEventListener("dragleave", () => {
		dropZone.classList.remove("dragover");
	});

	dropZone.addEventListener("drop", (e) => {
		e.preventDefault();
		dropZone.classList.remove("dragover");
	});

	fileInput.addEventListener("change", (e) => {
		enqueue(Array.from(e.target.files));
		fileInput.value = "";
	});

	cancelBtn.addEventListener("click", cancelAll);
	clearAllBtn.addEventListener("click", clearResults);
	document.addEventListener("keydown", (e) => {
		if (e.key === "Escape") cancelAll();
	});

	document.addEventListener("dragover", (e) => {
		if (e.dataTransfer?.types?.includes("Files")) {
			e.preventDefault();
			document.body.classList.add("dragging");
		}
	});
	document.addEventListener("dragleave", (e) => {
		if (e.dataTransfer?.types?.includes("Files")) {
			// only remove when leaving window
			if (e.clientX === 0 && e.clientY === 0) {
				document.body.classList.remove("dragging");
			}
		}
	});
	document.addEventListener("drop", (e) => {
		if (!e.dataTransfer?.types?.includes("Files")) return;
		e.preventDefault();
		document.body.classList.remove("dragging");
		enqueue(dropItems(e.dataTransfer));
	});
}

// Must run synchronously inside the drop event; entries become invalid after it.
function dropItems(dataTransfer) {
	const items = [];
	for (const item of Array.from(dataTransfer.items || [])) {
		if (item.kind !== "file") continue;
		const entry = item.getAsFile() || item.webkitGetAsEntry();
		if (entry) {
			items.push(entry);
		}
	}
	if (items.length === 0) items.push(...Array.from(dataTransfer.files || []));
	return items;
}

const supportedFileName = /\.(jpe?g|png|gif|webp|bmp|tiff?|zip|cbz|rar|cbr)$/i;

async function walkEntry(entry, signal, found, nested) {
	if (signal.aborted) throw new DOMException("Cancelled", "AbortError");
	if (nested && (entry.name.startsWith(".") || entry.name === "__MACOSX")) {
		return;
	}
	if (entry.isFile) {
		if (
			nested &&
			entry.size > 1024 * 1024 * 5 && // If this is recursive and over 5 MB
			!supportedFileName.test(entry.name) // Skip the file if the extension isn't a known extension
		) {
			return;
		}
		const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
		found.push(file);
		return;
	}
	if (entry.isDirectory) {
		const reader = entry.createReader();
		for (;;) {
			const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
			if (batch.length === 0) break;
			for (const child of batch) {
				await walkEntry(child, signal, found, true);
			}
		}
	}
}

async function collectFiles(items, signal) {
	const found = [];
	for (const item of items) {
		if (item instanceof File) {
			found.push(item);
		} else {
			await walkEntry(item, signal, found, false);
		}
	}
	found.sort((a, b) =>
		(a.webkitRelativePath || a.name).localeCompare(b.webkitRelativePath || b.name, undefined, { numeric: true }),
	);
	return found;
}

// Drops during a run join it; otherwise a drop starts a new run. cancelAll aborts the active run.
let runController = new AbortController();

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

function showEmptyState() {
	if (resultsEl.querySelector(".file-card, .empty-state")) return;
	const empty = document.createElement("p");
	empty.className = "empty-state";
	empty.textContent = "No searches. Drop files to begin.";
	resultsEl.appendChild(empty);
}

function updateClearButton() {
	clearAllBtn.hidden = !resultsEl.querySelector(".file-card");
}

// Drops every result, including cards still hashing. The active run is
// cancelled first so the files in flight cannot add their cards back.
function clearResults() {
	if (activeRun) cancelAll();
	for (const state of resultStates) {
		state.dismissed = true;
		openSearches.delete(state);
		releasePreview(state);
	}
	resultStates.clear();
	resultsEl.replaceChildren();
	showEmptyState();
	updateClearButton();
}

async function loadDomains() {
	const response = await fetch("domains");
	if (!response.ok) throw new Error(response.statusText);
	const text = await response.text();
	return [
		...new Set(
			text
				.split("\n")
				.map((d) => d.trim())
				.filter(Boolean),
		),
	].sort();
}

const domainsReady = loadDomains()
	.then((list) => {
		domains = list;
		renderDomainFilter();
	})
	.catch((err) => {
		statusEl.textContent = `Failed to load domains: ${err.message}`;
		statusEl.classList.add("error");
		domains = [];
	});

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
	const img = document.createElement("img");
	img.width = 16;
	img.height = 16;
	img.loading = "lazy";
	img.referrerPolicy = "no-referrer";
	img.alt = domain;
	img.title = domain;
	img.addEventListener("error", () => {
		if (img.dataset.fallbackTried) {
			const fallback = document.createElement("span");
			fallback.className = "domain-name";
			fallback.textContent = domain;
			img.replaceWith(fallback);
			return;
		}
		const looksLikeHostname = domain.includes(".") && !/\s|\//.test(domain);
		if (looksLikeHostname) {
			img.dataset.fallbackTried = "true";
			img.src = `https://${encodeURIComponent(domain)}/favicon.ico`;
		} else {
			const fallback = document.createElement("span");
			fallback.className = "domain-name";
			fallback.textContent = domain;
			img.replaceWith(fallback);
		}
	});
	img.src = `static/${encodeURIComponent(domain)}.ico?v=${version}`;
	return img;
}

function makeCover(url, alt) {
	const img = document.createElement("img");
	img.className = "cover-thumb";
	img.alt = alt;
	img.title = alt;
	img.referrerPolicy = "no-referrer";
	img.draggable = false;
	img.addEventListener("error", () => setCoverSource(img, noImageURL));
	setCoverSource(img, url || noImageURL);
	return img;
}

function setCoverSource(img, url) {
	if (url !== noImageURL) delete img.dataset.noImage;
	if (img.dataset.noImage) return;
	if (url === noImageURL) {
		console.log("replacing", img.src, "with the fallback image");
		img.dataset.noImage = "true";
	}
	img.src = url;
}

function idLink(domain, id) {
	const url = sourceURL(domain, id);
	if (url) {
		const link = document.createElement("a");
		link.href = url;
		link.target = "_blank";
		link.rel = "noopener noreferrer";
		link.title = domain;
		if (domain) {
			link.appendChild(makeDomainIcon(domain));
			link.append(" ");
		}
		link.append(id);
		return link;
	}
	const span = document.createElement("span");
	span.title = domain || "";
	if (domain) {
		span.appendChild(makeDomainIcon(domain));
		span.append(" ", `${domain} ${id}`);
	} else {
		span.append(id);
	}
	return span;
}

function idKey(id) {
	return `${id?.Domain}:${id?.ID}`;
}

function cardMatchesFilter(card) {
	const matches = card.Matches ?? [];
	if (!includeAHash.checked && !matches.some((m) => m.Hash?.Kind !== "ahash")) {
		return false;
	}
	if (selectedDomains.size === 0) return true;
	for (const eid of [card.ID, ...(card.EquivalentIDs ?? [])]) {
		if (selectedDomains.has(eid?.Domain)) return true;
	}
	return false;
}

function renderDomainFilter() {
	domainFilterItems.replaceChildren();
	for (const domain of domains) {
		const option = document.createElement("button");
		option.classList = "menu-item";
		option.type = "button";
		option.dataset.bsValue = domain;
		option.appendChild(makeDomainIcon(domain));
		option.append(domain);
		const check = document.createElement("img");
		check.src = checkURL;
		check.classList = "menu-item-check";
		option.appendChild(check);
		domainFilterItems.appendChild(option);
	}
	const combobox = window.Combobox?.getOrCreateInstance(domainFilter);
	combobox.setValue(selectedDomains.values().toArray());
}

function reFilterResults() {
	for (const search of openSearches) {
		search.applyFilter?.();
	}
}

function updateDomains() {
	selectedDomains.clear();
	const combobox = window.Combobox?.getOrCreateInstance(domainFilter);
	for (const item of combobox.value()) {
		selectedDomains.add(item);
	}
}

exactOnlyInput.addEventListener("change", () => {
	for (const search of openSearches) {
		search.refresh();
	}
	reFilterResults();
});

includeAHash.addEventListener("change", () => {
	for (const search of openSearches) {
		if (!search.hashesSent.has("ahash")) {
			search.refresh();
		}
	}
	reFilterResults();
});

domainFilter.addEventListener("change", () => {
	updateDomains();
	reFilterResults();
});

domainFilterClear.addEventListener("click", () => {
	selectedDomains.clear();
	const combobox = window.Combobox?.getOrCreateInstance(domainFilter);
	combobox.setValue([]);
	reFilterResults();
});

// Calls an endpoint that reports its outcome in the JSON "msg" field.
// A 204 response has no body; an error is reported as a non-2xx status.
async function callIDEndpoint(endpoint, params) {
	const response = await fetch(`${endpoint}?${params.toString()}`);
	let msg = "";
	try {
		msg = (await response.json())?.msg ?? "";
	} catch {
		// No body (e.g. 204 No Content)
	}
	if (!response.ok) {
		throw new Error(msg || response.statusText);
	}
	return msg;
}

// Every open file search, so a change can refresh the ones showing the changed IDs.
const openSearches = new Set();

includeAHash.addEventListener("change", () => {
	for (const search of openSearches) {
		search.refresh?.();
	}
});

// Every search card's state, including cards that are still hashing and so are
// not in openSearches yet, so they can be dismissed and release their previews.
const resultStates = new Set();

// Refreshes the search that made a change and every other open search showing one of the changed IDs.
function refreshAffected(ids, origin) {
	const keys = new Set(ids.map(idKey));
	const refreshes = new Set([origin]);
	for (const search of openSearches) {
		if ((search.candidateIDs ?? []).some((eid) => keys.has(idKey(eid)))) {
			refreshes.add(search.refresh);
		}
	}
	return Promise.all([...refreshes].map((refresh) => refresh()));
}

function associateIDs(existingID, newDomain, newID) {
	const params = new URLSearchParams({
		domain: existingID.Domain ?? "",
		id: existingID.ID ?? "",
		newDomain,
		newID,
	});
	return callIDEndpoint("associate_ids", params);
}

function disassociateID(id) {
	const params = new URLSearchParams({
		domain: id.Domain ?? "",
		id: id.ID ?? "",
	});
	return callIDEndpoint("disassociate_id", params);
}

function makeRemoveButton(label) {
	const btn = document.createElement("button");
	btn.type = "button";
	btn.className = "chip-remove";
	btn.textContent = "×";
	btn.setAttribute("aria-label", label);
	return btn;
}

function makeChip(eid, refreshMatches) {
	const chip = document.createElement("span");
	chip.className = "chip";
	chip.appendChild(idLink(eid.Domain ?? "", eid.ID ?? ""));
	const removeBtn = makeRemoveButton(`Remove ${eid.Domain ?? ""}:${eid.ID ?? ""} from group`);
	removeBtn.addEventListener("click", async () => {
		removeBtn.disabled = true;
		try {
			await disassociateID(eid);
			// Re-query the search instead of editing the chip list locally.
			await refreshAffected([eid], refreshMatches);
			removeBtn.disabled = false;
		} catch (err) {
			removeBtn.title = `Failed: ${err.message}`;
			removeBtn.disabled = false;
		}
	});
	chip.appendChild(removeBtn);
	return chip;
}

function addChip(chipsEl, eid, refreshMatches) {
	if (!eid?.Domain || eid?.ID == null || eid.ID === "") return;
	chipsEl.idKeys ??= new Set();
	const key = idKey(eid);
	if (chipsEl.idKeys.has(key)) return;
	chipsEl.idKeys.add(key);
	chipsEl.appendChild(makeChip(eid, refreshMatches));
}

function setCardStatus(statusEl, text, isError = false) {
	statusEl.textContent = text;
	statusEl.classList.toggle("error", isError);
}

// Drag state for grouping IDs: the card currently being dragged.
let cardDrag = null;

// Sources of every ID in a card's group, including the card's own ID.
function groupDomains(match) {
	return new Set([match.ID, ...match.EquivalentIDs].map((eid) => eid.Domain).filter(Boolean));
}

// The server rejects a grouping when both groups already share a source.
function groupsConflict(a, b) {
	return [...a].some((domain) => b.has(domain));
}

// Dropping one result card onto another groups their IDs. The add-ID form
// remains as the keyboard-accessible alternative.
function makeCardDraggable(el, match, statusEl, refreshMatches) {
	el.draggable = true;
	el.title = "Drag onto another result to group their IDs";

	el.addEventListener("dragstart", (e) => {
		if (e.target !== el) {
			return;
		}
		// Let form controls handle their own drag/selection behaviour.
		if (e.target.closest?.("input, select, button, textarea")) {
			e.preventDefault();
			return;
		}
		cardDrag = { id: match.ID, domains: groupDomains(match) };
		const dragImage = el.querySelector("img.cover-thumb");
		if (dragImage) e.dataTransfer.setDragImage(dragImage, 24, 24);
		e.dataTransfer.items.add(`${match.ID.Domain}:${match.ID.ID}`, "text/plain");
		el.classList.add("dragging");
		e.dataTransfer.effectAllowed = "copy"; // This would be link but chrome is a piece of shit
	});

	el.addEventListener("dragend", () => {
		cardDrag = null;
		el.classList.remove("dragging");
		const cards = document.querySelectorAll(".match-card.drop-target, .match-card.drop-blocked");
		for (const card of cards) {
			card.classList.remove("drop-target", "drop-blocked");
		}
	});

	el.addEventListener("dragenter", (e) => {
		e.dataTransfer.effectAllowed = "copy";
		if (!cardDrag || cardDrag.el === el) return;
		const dragged = cardDrag.id;
		if (!dragged?.Domain || dragged.ID == null || dragged.ID === "") return;
		e.preventDefault();
	});

	el.addEventListener("dragover", (e) => {
		if (!cardDrag || cardDrag.el === el) return;
		const dragged = cardDrag.id;
		if (!dragged?.Domain || dragged.ID == null || dragged.ID === "") return;
		e.preventDefault();
		if (groupsConflict(cardDrag.domains, groupDomains(match))) {
			e.dataTransfer.dropEffect = "none";
			el.classList.remove("drop-target");
			el.classList.add("drop-blocked");
			return;
		}
		e.dataTransfer.dropEffect = "copy";
		el.classList.remove("drop-blocked");
		el.classList.add("drop-target");
	});

	el.addEventListener("dragleave", (e) => {
		if (!el.contains(e.relatedTarget)) {
			el.classList.remove("drop-target", "drop-blocked");
		}
	});

	el.addEventListener("drop", async (e) => {
		if (!cardDrag || cardDrag.el === el) return;
		e.preventDefault();
		e.stopPropagation();
		const dragged = cardDrag;
		cardDrag = null;
		el.classList.remove("drop-target", "drop-blocked");
		if (idKey(dragged.id) === idKey(match.ID)) return;
		if (groupsConflict(dragged.domains, groupDomains(match))) {
			setCardStatus(statusEl, "Cannot group two IDs from the same source", true);
			return;
		}
		setCardStatus(statusEl, "Grouping…");
		try {
			const msg = await associateIDs(match.ID, dragged.id.Domain, dragged.id.ID);
			if (msg === "New ID added") {
				setCardStatus(statusEl, "Grouped");
				// Re-query the affected searches so the server's grouping is
				// reflected instead of merging the chip lists locally.
				await refreshAffected([match.ID, dragged.id], refreshMatches);
			} else {
				// The server reports failures as 200 with the error in msg.
				setCardStatus(statusEl, msg, true);
			}
		} catch (err) {
			setCardStatus(statusEl, err.message, true);
		} finally {
			dragged.el.classList.remove("dragging");
		}
	});
}

// Disassociates the card's own ID from its group, then refreshes the search so
// former group members are no longer shown as equivalents of this ID.
function makeUngroupButton(id, refreshMatches) {
	const btn = makeRemoveButton(`Remove ${id.Domain ?? ""}:${id.ID ?? ""} from group`);
	btn.addEventListener("click", async () => {
		btn.disabled = true;
		try {
			await disassociateID(id);
			await refreshAffected([id], refreshMatches);
			btn.disabled = false;
		} catch (err) {
			btn.title = `Failed: ${err.message}`;
			btn.disabled = false;
		}
	});
	return btn;
}

// Every distinct ID shown in a search, so the group form can suggest them.
function collectCandidateIDs(cards) {
	const seen = new Map();
	for (const card of cards) {
		for (const eid of [card.ID, ...(card.EquivalentIDs ?? [])]) {
			if (!eid?.Domain || eid.ID == null || eid.ID === "") continue;
			const key = idKey(eid);
			if (!seen.has(key)) seen.set(key, { Domain: eid.Domain, ID: eid.ID });
		}
	}
	return [...seen.values()];
}

let groupSuggestionSeq = 0;

// Groups the card's ID with a second ID entered by the user. The input offers
// IDs from the same search that are not yet grouped with this card, but any
// text can still be typed.
function makeGroupForm(match, chipsEl, refreshMatches, cardState) {
	const form = document.createElement("form");
	form.className = "group-form";
	const domainSelect = document.createElement("select");
	domainSelect.setAttribute("aria-label", "Source of the new ID");
	for (const domain of domains) {
		const option = document.createElement("option");
		option.value = domain;
		option.textContent = domain;
		domainSelect.appendChild(option);
	}
	// The server rejects grouping two IDs from the same source.
	const other = domains.find((d) => d !== match.ID?.Domain);
	if (other) domainSelect.value = other;
	const idInput = document.createElement("input");
	idInput.type = "text";
	idInput.placeholder = "New ID";
	idInput.required = true;
	idInput.autocomplete = "off";
	idInput.setAttribute("aria-label", "New ID to group with this result");
	const suggestWrap = document.createElement("div");
	suggestWrap.className = "group-suggest";
	const suggestions = document.createElement("ul");
	suggestions.className = "group-suggest-list";
	suggestions.id = `group-suggestions-${++groupSuggestionSeq}`;
	suggestions.setAttribute("role", "listbox");
	suggestions.hidden = true;
	idInput.setAttribute("role", "combobox");
	idInput.setAttribute("aria-autocomplete", "list");
	idInput.setAttribute("aria-expanded", "false");
	idInput.setAttribute("aria-controls", suggestions.id);
	suggestWrap.append(idInput, suggestions);

	const candidateValues = () => {
		const selected = domainSelect.value;
		if (selected === match.ID?.Domain) return [];
		const grouped = new Set(chipsEl.idKeys ?? []);
		grouped.add(idKey(match.ID));
		const query = idInput.value.trim().toLowerCase();
		return (cardState?.candidateIDs ?? [])
			.filter((eid) => eid.Domain === selected && !grouped.has(idKey(eid)))
			.map((eid) => String(eid.ID))
			.filter((value) => value.toLowerCase().includes(query));
	};
	const closeSuggestions = () => {
		suggestions.hidden = true;
		idInput.setAttribute("aria-expanded", "false");
		idInput.removeAttribute("aria-activedescendant");
	};
	const setActive = (index) => {
		const items = suggestions.children;
		const next = (index + items.length) % items.length;
		for (const [i, item] of [...items].entries()) {
			item.classList.toggle("active", i === next);
		}
		idInput.setAttribute("aria-activedescendant", items[next].id);
		items[next].scrollIntoView({ block: "nearest" });
	};
	const pickSuggestion = (value) => {
		idInput.value = value;
		closeSuggestions();
	};
	const renderSuggestions = () => {
		suggestions.replaceChildren();
		let index = 0;
		for (const value of candidateValues()) {
			const item = document.createElement("li");
			item.id = `${suggestions.id}-${index++}`;
			item.setAttribute("role", "option");
			item.textContent = value;
			// mousedown keeps focus in the input so the list stays open until the click lands.
			item.addEventListener("mousedown", (e) => {
				e.preventDefault();
				pickSuggestion(value);
			});
			suggestions.appendChild(item);
		}
		suggestions.hidden = suggestions.children.length === 0;
		idInput.setAttribute("aria-expanded", String(!suggestions.hidden));
	};
	idInput.addEventListener("focus", renderSuggestions);
	idInput.addEventListener("input", renderSuggestions);
	idInput.addEventListener("blur", closeSuggestions);
	domainSelect.addEventListener("change", renderSuggestions);
	idInput.addEventListener("keydown", (e) => {
		if (suggestions.hidden) return;
		const active = suggestions.querySelector(".active");
		const activeIndex = active ? [...suggestions.children].indexOf(active) : -1;
		if (e.key === "ArrowDown") {
			e.preventDefault();
			setActive(activeIndex + 1);
		} else if (e.key === "ArrowUp") {
			e.preventDefault();
			setActive(activeIndex < 0 ? suggestions.children.length - 1 : activeIndex - 1);
		} else if (e.key === "Enter" && active) {
			e.preventDefault();
			pickSuggestion(active.textContent);
		} else if (e.key === "Escape") {
			e.stopPropagation();
			closeSuggestions();
		}
	});
	const submit = document.createElement("button");
	submit.type = "submit";
	submit.textContent = "Group";
	const status = document.createElement("span");
	status.className = "group-status";
	form.append(domainSelect, suggestWrap, submit, status);
	form.addEventListener("submit", async (e) => {
		e.preventDefault();
		const newID = idInput.value.trim();
		if (!newID) return;
		submit.disabled = true;
		status.textContent = "Grouping…";
		status.classList.remove("error");
		try {
			const msg = await associateIDs(match.ID, domainSelect.value, newID);
			// The server reports failures as 200 with the error in msg.
			if (msg === "New ID added") {
				idInput.value = "";
				status.textContent = msg;
				await refreshAffected([match.ID, { Domain: domainSelect.value, ID: newID }], refreshMatches);
			} else {
				status.classList.add("error");
				status.textContent = msg;
			}
		} catch (err) {
			status.textContent = err.message;
			status.classList.add("error");
		} finally {
			submit.disabled = false;
		}
	});
	return form;
}

function renderMatch(match, cardState, searchHash, refreshMatches) {
	const url = sourceURL(match.ID.Domain, match.ID.ID);

	const el = document.createElement("article");
	el.className = "match-card";

	const idWrap = document.createElement("div");
	idWrap.className = "match-id";
	idWrap.appendChild(idLink(match.ID.Domain, match.ID.ID));
	el.appendChild(idWrap);

	const thumb = makeCover(match.ImageURL, `${match.ID.ID} ${match.ID.Domain}`);
	if (url) {
		const imgA = document.createElement("a");
		imgA.href = url;
		imgA.appendChild(thumb);
		el.appendChild(imgA);
	} else {
		el.appendChild(thumb);
	}

	const chips = document.createElement("div");
	chips.className = "chips";
	for (const eid of match.EquivalentIDs) addChip(chips, eid, refreshMatches);
	idWrap.appendChild(makeUngroupButton(match.ID, refreshMatches));

	const compareBtn = document.createElement("button");
	compareBtn.type = "button";
	compareBtn.textContent = "Compare stored";
	const comparePanel = document.createElement("div");
	comparePanel.className = "compare-panel";
	compareBtn.addEventListener("click", () => compareStored(match.ID, searchHash, comparePanel));
	el.append(compareBtn, comparePanel);

	const matches = Array.isArray(match.Matches) && match.Matches.length ? match.Matches : [match];
	const byKind = new Map();
	for (const m of matches) byKind.set(m.Hash.Kind, m);
	const fixedKinds = ["ahash", "dhash", "phash"];
	const details = document.createElement("div");
	details.className = "match-details";
	// Always render the same three kinds so cards line up identically.
	for (const kind of fixedKinds) {
		const m = byKind.get(kind);
		const row = document.createElement("div");
		row.className = "match-row";
		const dist = document.createElement("span");
		dist.className = "match-distance";
		dist.textContent = m ? `Distance: ${m.Distance}` : "Distance: —";
		const kindEl = document.createElement("span");
		kindEl.className = "match-kind";
		kindEl.textContent = kind;
		row.append(dist, " ", kindEl);
		details.appendChild(row);
	}
	// Render any unexpected hash kinds as well.
	for (const [kind, m] of byKind) {
		if (fixedKinds.includes(kind)) continue;
		const row = document.createElement("div");
		row.className = "match-row";
		const dist = document.createElement("span");
		dist.className = "match-distance";
		dist.textContent = `Distance: ${m.Distance}`;
		const kindEl = document.createElement("span");
		kindEl.className = "match-kind";
		kindEl.textContent = kind;
		row.append(dist, " ", kindEl);
		details.appendChild(row);
	}
	el.appendChild(details);

	// An empty chips container is invisible but must stay in the DOM so
	// chips added after grouping an ID are visible.
	el.appendChild(chips);
	el.appendChild(makeGroupForm(match, chips, refreshMatches, cardState));

	const dropStatus = document.createElement("p");
	dropStatus.className = "group-status drop-status";
	dropStatus.setAttribute("aria-live", "polite");
	el.appendChild(dropStatus);
	makeCardDraggable(el, match, dropStatus, refreshMatches);

	return el;
}

// Renders the cards whose IDs are already in one group inside a single labelled
// container so it is obvious at a glance that they are linked. Without this the
// two IDs show up as unrelated cards, each only hinting at the other via a chip.
function renderCluster(cards, cardState, searchHash, refreshMatches) {
	const cluster = document.createElement("div");
	cluster.className = "match-cluster";
	cluster.setAttribute("role", "group");
	cluster.setAttribute("aria-label", `Linked group of ${cards.length} IDs`);

	const label = document.createElement("div");
	label.className = "match-cluster-label";
	label.append(`🔗 Linked group · ${cards.length} IDs`);
	cluster.appendChild(label);

	const inner = document.createElement("div");
	inner.className = "match-cluster-cards";
	for (const card of cards) {
		inner.appendChild(renderMatch(card, cardState, searchHash, refreshMatches));
	}
	cluster.appendChild(inner);
	return cluster;
}

// Groups cards that share the same set of equivalent IDs so already-linked IDs
// render together. cards must already be sorted; each cluster keeps that order
// and the clusters stay ordered by their best (first) card.
function clusterCards(cards) {
	const byKey = new Map();
	for (const card of cards) {
		const groupIDs = new Set(card.EquivalentIDs.map(idKey));
		groupIDs.add(idKey(card.ID));
		const key = [...groupIDs].sort().join("\n");
		let cluster = byKey.get(key);
		if (!cluster) {
			cluster = [];
			byKey.set(key, cluster);
		}
		cluster.push(card);
	}
	return Array.from(byKey.values());
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
		if (!run.signal.aborted) processStatusEl.textContent = `Failed to load hasher: ${err.message}`;
	});

	processStatusEl.setAttribute("aria-live", "polite");
	processStatusEl.textContent = "Scanning...";
	const batchStart = performance.now();
	try {
		appendFiles(run, await collectFiles(items, run.signal));
		if (run.files.length === 0) {
			processStatusEl.textContent = "No supported files found";
			return;
		}
		while (run.batchInFlight && !run.signal.aborted) {
			await run.batchInFlight;
		}
		const batchMs = performance.now() - batchStart;
		const lastRun = `Last run: ${(batchMs / 1000).toFixed(1)} s, ${run.done} of ${run.files.length} files, avg hash ${run.hashCount ? (run.hashMsTotal / run.hashCount).toFixed(0) : "–"} ms`;
		processStatusEl.textContent = run.signal.aborted ? `Cancelled. ${lastRun}` : lastRun;
		if (!resultsEl.querySelector(".file-card")) {
			showEmptyState();
		}
	} catch (err) {
		processStatusEl.textContent = err.name === "AbortError" ? "Cancelled" : `Failed to read: ${err.message}`;
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

const hashBatchSize = 8;

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
	processStatusEl.textContent = `Hashed ${run.hashed} of ${run.files.length}`;
}

function finishRun(run) {
	if (run.finished) return;
	run.finished = true;
	run.queued = [];
	for (const { worker } of run.workers) stopHashWorker(worker);
	if (activeRun === run) activeRun = null;
	cancelBtn.hidden = true;
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

// Combines raw match rows that refer to the same ID into one card's worth of
// data, sorted by the closest match.
function combineResults(results) {
	// group by hash kind, sort each group by distance, keep first 10
	const groups = new Map([
		["phash", []],
		["dhash", []],
		["ahash", []],
	]);
	for (const r of results) {
		if (!groups.has(r.Hash.Kind)) groups.set(r.Hash.Kind, []);
		groups.get(r.Hash.Kind).push(r);
	}
	const limited = [];
	for (const [_, arr] of groups) {
		arr.sort((a, b) => a.Distance - b.Distance || a.ID.Domain.localeCompare(b.ID.Domain));
		limited.push(...arr.slice(0, 10));
	}
	// sort all by distance then source
	limited.sort((a, b) => a.Distance - b.Distance || a.ID.Domain.localeCompare(b.ID.Domain));

	// Combine results that refer to the same ID into a single card.
	const combinedMap = new Map();
	for (const r of limited) {
		const key = `${r.ID.Domain}:${r.ID.ID}`;
		if (!combinedMap.has(key)) {
			combinedMap.set(key, {
				ID: r.ID,
				ImageURL: r.ImageURL || "",
				Matches: [],
				EquivalentIDs: [],
				equivalentKeys: new Set(),
			});
		}
		const combined = combinedMap.get(key);
		combined.Matches.push(r);
		if (!combined.ImageURL) combined.ImageURL = r.ImageURL || "";
		for (const eid of r.EquivalentIDs) {
			const eidKey = `${eid.Domain}:${eid.ID}`;
			if (!combined.equivalentKeys.has(eidKey)) {
				combined.equivalentKeys.add(eidKey);
				combined.EquivalentIDs.push(eid);
			}
		}
	}
	const combined = Array.from(combinedMap.values());
	for (const c of combined) {
		c.Matches.sort((a, b) => a.Distance - b.Distance || a.Hash.Kind.localeCompare(b.Hash.Kind));
		c.minDistance = Math.min(...c.Matches.map((m) => m.Distance));
	}
	combined.sort((a, b) => {
		return a.minDistance - b.minDistance || a.ID.Domain.localeCompare(b.ID.Domain) || a.ID.ID.localeCompare(b.ID.ID);
	});
	return combined;
}

async function processFile(file, pendingHash, signal) {
	// remove empty state
	const empty = resultsEl.querySelector(".empty-state");
	if (empty) empty.remove();

	const card = document.createElement("section");
	card.className = "file-card";

	const header = document.createElement("header");
	const title = document.createElement("h2");
	title.textContent = file.name;
	const actions = document.createElement("div");
	actions.className = "card-actions";
	const refreshBtn = document.createElement("button");
	refreshBtn.className = "refresh-btn";
	refreshBtn.textContent = "↻";
	refreshBtn.setAttribute("aria-label", "Refresh search");
	refreshBtn.title = "Refresh search";
	refreshBtn.disabled = true;
	const closeBtn = document.createElement("button");
	closeBtn.className = "close-btn";
	closeBtn.textContent = "×";
	closeBtn.setAttribute("aria-label", "Dismiss search");
	actions.append(refreshBtn, closeBtn);
	header.append(title, actions);
	card.appendChild(header);

	const status = document.createElement("p");
	status.textContent = "Computing hash...";
	card.appendChild(status);
	resultsEl.appendChild(card);

	const state = { card, dismissed: false, previewUrl: null, hashesSent: new Set() };
	state.previewUrl = URL.createObjectURL(file);
	resultStates.add(state);
	updateClearButton();
	const el = document.createElement("article");
	el.className = "match-card";

	const searchImage = makeCover(state.previewUrl, file.name);
	searchImage.draggable = true;
	el.appendChild(searchImage);

	closeBtn.addEventListener("click", () => {
		state.dismissed = true;
		resultStates.delete(state);
		openSearches.delete(state);
		releasePreview(state);
		card.remove();
		showEmptyState();
		updateClearButton();
	});

	const result = await pendingHash;
	try {
		if (!result?.hash?.image) {
			showPreview(state, searchImage, file);
			if (result.error) throw result.error;
		} else {
			showPreview(state, searchImage, new Blob([result.hash.image]));
			result.hash.image = null;
		}
	} catch (err) {
		if (state.dismissed) {
			if (signal.aborted) status.textContent = "Cancelled";
			return;
		}
		status.textContent = `Error: ${err.message}`;
		status.className = "error";
		return;
	}

	if (state.dismissed) return;

	if (signal.aborted) {
		status.textContent = "Cancelled";
		return;
	}

	if (result.hash.error) {
		status.textContent = result.hash.error;
		status.className = "error";
		return;
	}

	status.remove();
	const metaContainer = document.createElement("div");
	metaContainer.className = "meta-info";

	const meta = document.createElement("p");
	meta.className = "meta";
	const entryName = String(result.hash.entry ?? "")
		.split("/")
		.pop();
	meta.textContent = `${entryName} — ${result.hash.format} — ${result.hash.width}×${result.hash.height}`;
	metaContainer.appendChild(meta);

	const serverStatus = document.createElement("p");
	serverStatus.className = "server-status";
	metaContainer.appendChild(serverStatus);

	const hashes = document.createElement("p");
	hashes.className = "hashes";
	hashes.setHTML(`ahash ${result.hash.ahash}<br/>dhash ${result.hash.dhash}<br/>phash ${result.hash.phash}`);
	metaContainer.appendChild(hashes);

	el.appendChild(metaContainer);
	card.appendChild(el);

	const searchHash = {
		ahash: result.hash.ahash,
		dhash: result.hash.dhash,
		phash: result.hash.phash,
	};

	const grid = document.createElement("div");
	grid.className = "match-grid";
	card.appendChild(grid);

	const ctx = {
		state,
		signal,
		hash: result.hash,
		searchHash,
		grid,
		serverStatus,
		refreshBtn,
		requestSeq: 0,
		pendingLookups: 0,
	};

	refreshBtn.addEventListener("click", () => {
		refreshMatches(ctx);
	});

	state.refresh = () => refreshMatches(ctx);
	state.applyFilter = () => renderGrid(ctx);
	openSearches.add(state);
	await refreshMatches(ctx);
}

function renderGrid(ctx) {
	const { state, grid, serverStatus, searchHash } = ctx;
	if (state.combined == null) return;
	const visible = state.combined.filter(cardMatchesFilter);
	grid.replaceChildren();
	// Report no matches if they are hidden by a filter
	if (visible.length === 0) {
		serverStatus.textContent = "No hashes found";
		serverStatus.classList.add("error");
		return;
	}
	const onRefresh = () => refreshMatches(ctx);
	for (const cluster of clusterCards(visible)) {
		if (cluster.length > 1) {
			grid.appendChild(renderCluster(cluster, state, searchHash, onRefresh));
		} else {
			grid.appendChild(renderMatch(cluster[0], state, searchHash, onRefresh));
		}
	}
	serverStatus.classList.remove("error");
	if (selectedDomains.size === 0) {
		serverStatus.textContent = state.summary;
		return;
	}
	serverStatus.textContent = `${state.summary} · ${visible.length} of ${state.combined.length} shown`;
}

// Re-runs the lookup so grouping changes made elsewhere show up here.
async function runMatchLookup(ctx) {
	const { state, signal, hash, serverStatus } = ctx;
	await domainsReady;
	const seq = ++ctx.requestSeq;
	let response;
	try {
		const params = new URLSearchParams();
		if (includeAHash.checked) {
			state.hashesSent.add("ahash");
			params.set("ahash", hash.ahash);
		}
		params.set("dhash", hash.dhash);
		state.hashesSent.add("dhash");
		params.set("phash", hash.phash);
		state.hashesSent.add("phash");
		const max = Number.isInteger(maxDistInput.valueAsNumber) ? maxDistInput.valueAsNumber : 8;
		params.set("max", String(Math.min(8, Math.max(0, max))));
		params.set("exactOnly", exactOnlyInput.checked ? "true" : "false");
		params.set("images", "true");
		response = await fetch(`match_cover_hash?${params.toString()}`, {
			signal,
		});
	} catch (err) {
		if (state.dismissed || seq !== ctx.requestSeq) return;
		if (signal.aborted) {
			serverStatus.textContent = "Cancelled";
			return;
		}
		serverStatus.textContent = `Network error: ${err.message}`;
		serverStatus.className = "error";
		return;
	}

	if (state.dismissed || seq !== ctx.requestSeq) return;

	let data;
	try {
		data = await response.json();
	} catch (err) {
		if (state.dismissed || seq !== ctx.requestSeq) return;
		if (signal.aborted) {
			serverStatus.textContent = "Cancelled";
			return;
		}
		serverStatus.textContent = `Invalid server response: ${err.message}`;
		serverStatus.className = "error";
		return;
	}

	if (state.dismissed || seq !== ctx.requestSeq) return;

	if (!response.ok) {
		serverStatus.textContent = data.msg || response.statusText;
		serverStatus.className = "error";
		return;
	}

	const results = data.results || [];
	const combined = combineResults(results);
	state.combined = combined;
	state.candidateIDs = collectCandidateIDs(combined);
	serverStatus.className = "server-status";
	state.summary = data.msg || `${results.length} match${results.length === 1 ? "" : "es"}`;
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
function releasePreview(state) {
	if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
	state.previewUrl = null;
}

init();
