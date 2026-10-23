'use strict';
// luci_render.js renders a page of luci-app-rollcall outside a browser, with
// the LuCI modules it uses replaced by small stand-ins, runs the clicks a
// scenario names, and prints what a person would see as one JSON object. It
// is test tooling for cmd/rollcall/luci_test.go and is never shipped.
//
// usage: node luci_render.js <scenario.json>
//
// The scenario is {"view": <path of the view .js>, "status": <the report the
// page gets>, "replies": {<command>: <reply object>}, "actions": [...]}, and
// each action is {"click": "<button label>"}, {"check": "<element id>"} or
// {"set": ["<element id>", "<value>"]}. A button is looked for in the open
// dialog first, then in the page.
//
// The output is {"page": text, "modal": text or null, "alerts": [{"class",
// "text"}], "strong": [text], "execs": [{"command", "params", "env"}],
// "notes": [text], "problems": [text]}. A child that LuCI's E() would insert
// as markup (a bare string) is a problem, so a test fails on it.

const fs = require('fs');

const scenario = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

const problems = [];
const execs = [];
const notes = [];
let modal = null;

function isNode(x) {
	return x !== null && typeof x === 'object' && !Array.isArray(x) &&
		(Object.prototype.hasOwnProperty.call(x, 'tag') || Object.prototype.hasOwnProperty.call(x, 'text'));
}

function append(el, children) {
	if (children === undefined || children === null) {
		return;
	}
	if (Array.isArray(children)) {
		children.forEach(function (c) {
			if (isNode(c)) {
				el.children.push(c);
			} else if (c !== null && c !== undefined) {
				el.children.push({ text: String(c) });
			}
		});
		return;
	}
	if (isNode(children)) {
		el.children.push(children);
		return;
	}
	problems.push('a bare string child of <' + el.tag + '> would be markup: ' + String(children));
}

function E(tag, attrs, children) {
	if (children === undefined && (Array.isArray(attrs) || isNode(attrs) || typeof attrs === 'string')) {
		children = attrs;
		attrs = {};
	}
	const el = { tag: tag, attrs: attrs || {}, children: [], value: '', checked: false };
	if (el.attrs.value !== undefined) {
		el.value = String(el.attrs.value);
	}
	if (el.attrs.checked) {
		el.checked = true;
	}
	append(el, children);
	return el;
}

String.prototype.format = function () {
	const args = arguments;
	let i = 0;
	return this.replace(/%s/g, function () {
		return String(args[i++]);
	});
};

function translate(s) {
	return s;
}

function replyFor(params) {
	if (params && params[0] === 'status') {
		return JSON.stringify(scenario.status);
	}
	const replies = scenario.replies || {};
	const key = params && params[0];
	return JSON.stringify(Object.prototype.hasOwnProperty.call(replies, key) ? replies[key] : { ok: true, message: 'Done.' });
}

const stubs = {
	view: { extend: function (o) { return o; } },
	dom: {
		content: function (box, children) {
			box.children = [];
			append(box, children);
		}
	},
	poll: { add: function () {} },
	rpc: {
		declare: function (opts) {
			return function () {
				const call = {};
				const args = arguments;
				opts.params.forEach(function (p, i) {
					call[p] = args[i];
				});
				execs.push({ command: call.command, params: call.params, env: call.env || null });
				return Promise.resolve({ code: 0, stdout: replyFor(call.params) + '\n' });
			};
		}
	},
	ui: {
		showModal: function (title, children) {
			modal = E('div', { 'class': 'modal' }, [ E('h4', {}, [ String(title) ]) ].concat(children));
			return modal;
		},
		hideModal: function () {
			modal = null;
		},
		addNotification: function (title, node) {
			notes.push(textOf(node));
		}
	},
	document: { createTextNode: function (s) { return { text: String(s) }; } }
};

const blocks = { div: 1, p: 1, tr: 1, h2: 1, h3: 1, h4: 1, li: 1, table: 1, ul: 1 };

function textOf(n) {
	if (!n) {
		return '';
	}
	if (!Object.prototype.hasOwnProperty.call(n, 'tag')) {
		return n.text;
	}
	let s = n.children.map(textOf).join(n.tag === 'tr' ? ' | ' : '');
	if (blocks[n.tag]) {
		s = '\n' + s + '\n';
	}
	return s;
}

function tidy(s) {
	return s.split('\n').map(function (l) { return l.trim(); }).filter(function (l) { return l !== ''; }).join('\n');
}

function walk(n, f) {
	if (!n || !Object.prototype.hasOwnProperty.call(n, 'tag')) {
		return;
	}
	f(n);
	n.children.forEach(function (c) { walk(c, f); });
}

function find(pred) {
	let hit = null;
	[ modal, page ].forEach(function (root) {
		if (hit) {
			return;
		}
		walk(root, function (n) {
			if (!hit && pred(n)) {
				hit = n;
			}
		});
	});
	return hit;
}

function flush() {
	return new Promise(function (resolve) { setImmediate(resolve); });
}

const src = fs.readFileSync(scenario.view, 'utf8');
const factory = new Function('view', 'dom', 'poll', 'rpc', 'ui', 'E', '_', 'document', src);
const viewObj = factory(stubs.view, stubs.dom, stubs.poll, stubs.rpc, stubs.ui, E, translate, stubs.document);
let page = viewObj.render(scenario.status);

async function main() {
	for (const a of scenario.actions || []) {
		if (a.click !== undefined) {
			const b = find(function (n) { return n.tag === 'button' && tidy(textOf(n)) === a.click; });
			if (!b) {
				problems.push('no button ' + a.click);
				continue;
			}
			await b.attrs.click();
		} else if (a.check !== undefined || a.set !== undefined) {
			const id = a.check !== undefined ? a.check : a.set[0];
			const el = find(function (n) { return n.attrs && n.attrs.id === id; });
			if (!el) {
				problems.push('no element #' + id);
				continue;
			}
			if (a.check !== undefined) {
				el.checked = true;
			} else {
				el.value = a.set[1];
			}
		}
		for (let i = 0; i < 10; i++) {
			await flush();
		}
	}
	const alerts = [];
	const strong = [];
	[ page, modal ].forEach(function (root) {
		walk(root, function (n) {
			const cls = String(n.attrs['class'] || '');
			if (cls.split(' ').indexOf('alert-message') >= 0) {
				alerts.push({ 'class': cls, text: tidy(textOf(n)) });
			}
			if (n.tag === 'strong') {
				strong.push(tidy(textOf(n)));
			}
		});
	});
	process.stdout.write(JSON.stringify({
		page: tidy(textOf(page)),
		modal: modal ? tidy(textOf(modal)) : null,
		alerts: alerts,
		strong: strong,
		execs: execs,
		notes: notes,
		problems: problems
	}) + '\n');
}

main().catch(function (e) {
	process.stderr.write(String(e && e.stack || e) + '\n');
	process.exit(1);
});
