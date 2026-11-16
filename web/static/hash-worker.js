const staticVersion = new URL(self.location.href).searchParams.get("v");
// Note the hash-worker is started from the /static path so these relative urls will resolve
// with the prefix /static/
const wasmExecURL = `wasm_exec.js?v=${staticVersion}`;
const wasmURL = `main.wasm?v=${staticVersion}`;
importScripts(wasmExecURL);

function waitForHashCover() {
	return new Promise((resolve, reject) => {
		const deadline = Date.now() + 15000;
		const timer = setInterval(() => {
			if (typeof hashCover === "function") {
				clearInterval(timer);
				resolve();
			} else if (Date.now() > deadline) {
				clearInterval(timer);
				reject(new Error("Timed out waiting for hasher"));
			}
		}, 50);
	});
}

async function loadWasm() {
	const go = new Go();
	let result;
	if (typeof WebAssembly.instantiateStreaming === "function") {
		result = await WebAssembly.instantiateStreaming(fetch(wasmURL), go.importObject);
	} else {
		const response = await fetch(wasmURL);
		const bytes = await response.arrayBuffer();
		result = await WebAssembly.instantiate(bytes, go.importObject);
	}
	go.run(result.instance);
	await waitForHashCover();
}

// Id 0 is reserved for the startup result.
loadWasm()
	.then(() => postMessage({ id: 0, ok: true }))
	.catch((err) => postMessage({ id: 0, ok: false, error: err.message }));

// Requests run one at a time so only one file's bytes are held per worker.
let queue = Promise.resolve();

onmessage = (e) => {
	queue = queue.then(() => hashRequest(e.data));
};

async function hashRequest({ id, file }) {
	try {
		const buffer = await file.arrayBuffer();
		const result = hashCover(file.name, new Uint8Array(buffer));
		postMessage({ id, ok: true, result, error: null });
	} catch (err) {
		postMessage({ id, ok: false, error: err.message });
	}
}
