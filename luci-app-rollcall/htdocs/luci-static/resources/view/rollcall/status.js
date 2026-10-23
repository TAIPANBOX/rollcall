'use strict';
'require view';
'require dom';
'require poll';
'require rpc';

/*
 * Status page: who is in this router's group, who sends to Telegram, what was
 * reported lately, and what is not working.
 *
 * Everything shown comes from `rollcall status --json`, whose fields are
 * written down in luci-app-rollcall/STATUS-JSON.md. Every value reaches the
 * page as a text node: E() gets its children as an array or an element, and
 * each value is wrapped in T(), so a router name or an incident text that
 * carries markup is shown as plain characters. The status report holds no
 * join code, token or key, and this page never asks for one.
 */

var ROLLCALL = '/usr/bin/rollcall';
var SCHEMA = 1;
var REFRESH_SECONDS = 30;

var callExec = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ]
});

/* A text node holding s. Every value from the daemon goes through here. */
function T(s) {
	return document.createTextNode(String(s == null ? '' : s));
}

/* The label tables are functions so that _() runs after the translations load. */
function roleLabels() {
	return {
		sender: _('sends to Telegram'),
		primary: _('primary admin'),
		backup: _('backup admin')
	};
}

function memberStateLabels() {
	return {
		up: _('up'),
		suspect: _('suspect: not heard from for a while'),
		silent: _('silent'),
		suspicious: _('suspicious: two different histories, see the alarm in the chat'),
		unheard: _('not heard from since this boot')
	};
}

function telegramLabels() {
	return {
		ok: _('reachable from this router'),
		not_configured: _('not configured for this group'),
		not_sender: _('this router does not send; a sender does'),
		not_bound: _('token set, chat not bound yet: bind it on the Admin tab'),
		bot_blocked: _('the bot was blocked in Telegram: unblock it; messages wait in the queue'),
		rate_limited: _('Telegram asks to slow down: messages wait, then go out'),
		tls_failed: _('cannot reach Telegram securely: certificate check failed; messages wait in the queue'),
		unreachable: _('Telegram cannot be reached from this router right now')
	};
}

function sandboxLabels() {
	return {
		enforced: _('running in its sandbox'),
		partial: _('running with some sandbox limits missing'),
		off: _('not sandboxed')
	};
}

function topologyLabels() {
	return {
		no_second_uplink: _('no second way out: outage reports arrive after recovery'),
		second_uplink: _('a member has its own second uplink: an outage of the main line can be reported as it happens'),
		overlay_sites: _('several sites over an overlay: a site that stays online reports the other site\'s loss as it happens')
	};
}

function hasKey(table, key) {
	return typeof key === 'string' && Object.prototype.hasOwnProperty.call(table, key);
}

function lookup(table, key, fallback) {
	return hasKey(table, key) ? table[key] : fallback;
}

function text(v) {
	return (v === null || v === undefined || v === '') ? '-' : String(v);
}

function yesNo(v) {
	return v ? _('yes') : _('no');
}

/* Reads the status report. A report the page cannot use comes back as
 * { problem: text } so the page can say so instead of rendering nothing. */
function loadStatus() {
	return callExec(ROLLCALL, [ 'status', '--json' ]).then(function (res) {
		var st;
		try {
			st = JSON.parse((res && res.stdout) || '');
		} catch (e) {
			return { problem: _('rollcall did not return a status report.') };
		}
		if (!st || typeof st !== 'object') {
			return { problem: _('rollcall did not return a status report.') };
		}
		if (st.schema !== SCHEMA) {
			return { problem: _('The status report has a format this page does not read. Update luci-app-rollcall and rollcall together.') };
		}
		return st;
	}, function () {
		return { problem: _('rollcall could not be run. Is the package installed, and is this login allowed to read its status?') };
	});
}

/* value is an array of child nodes. */
function labelRow(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'style': 'width:28%' }, [ T(label) ]),
		E('td', { 'class': 'td left' }, [].concat(value))
	]);
}

/* children is an array of child nodes. */
function alertBox(severity, children) {
	return E('div', { 'class': 'alert-message ' + severity }, [].concat(children));
}

function roleNames(roles) {
	var labels = roleLabels();
	return roles.map(function (r) {
		return lookup(labels, r, String(r));
	});
}

function memberTable(st) {
	var self = st.self || {};
	var members = Array.isArray(st.members) ? st.members : [];
	if (!members.length) {
		return E('p', {}, [ _('No members are known yet.') ]);
	}
	var states = memberStateLabels();
	var head = E('tr', { 'class': 'tr table-titles' }, [
		E('th', { 'class': 'th' }, [ _('Router') ]),
		E('th', { 'class': 'th' }, [ _('Roles') ]),
		E('th', { 'class': 'th' }, [ _('State') ]),
		E('th', { 'class': 'th' }, [ _('Last seen') ])
	]);
	var rows = members.map(function (m) {
		var roles = Array.isArray(m.roles) ? m.roles : [];
		var roleText = roles.length ? roleNames(roles).join(', ') : _('member');
		var name = text(m.name);
		if (self.name && m.name === self.name) {
			name = name + ' (' + _('this router') + ')';
		}
		var seen = (typeof m.last_seen_seconds === 'number')
			? m.last_seen_seconds + ' ' + _('s ago')
			: _('never');
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left' }, [ T(name) ]),
			E('td', { 'class': 'td left' }, [ T(roleText) ]),
			E('td', { 'class': 'td left' }, [ T(lookup(states, m.state, text(m.state))) ]),
			E('td', { 'class': 'td left' }, [ T(seen) ])
		]);
	});
	return E('table', { 'class': 'table' }, [ head ].concat(rows));
}

function incidentTable(st) {
	var incidents = Array.isArray(st.incidents) ? st.incidents : [];
	if (!incidents.length) {
		return E('p', {}, [ _('Nothing has been reported. A quiet group sends nothing.') ]);
	}
	var head = E('tr', { 'class': 'tr table-titles' }, [
		E('th', { 'class': 'th' }, [ _('Time') ]),
		E('th', { 'class': 'th' }, [ _('What was reported') ]),
		E('th', { 'class': 'th' }, [ _('Confirmed') ]),
		E('th', { 'class': 'th' }, [ _('Sent') ])
	]);
	var rows = incidents.map(function (inc) {
		var confirmed = (typeof inc.confirmed_by === 'number' && typeof inc.members === 'number')
			? _('confirmed by') + ' ' + inc.confirmed_by + ' ' + _('of') + ' ' + inc.members
			: '-';
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left' }, [ T(text(inc.time)) ]),
			E('td', { 'class': 'td left' }, [ T(text(inc.text)) ]),
			E('td', { 'class': 'td left' }, [ T(confirmed) ]),
			E('td', { 'class': 'td left' }, [ inc.delivered ? _('sent') : _('waiting') ])
		]);
	});
	return E('table', { 'class': 'table' }, [ head ].concat(rows));
}

function discoveryNode(st) {
	var problems = Array.isArray(st.discovery) ? st.discovery : [];
	if (!problems.length) {
		return E('span', {}, [ _('no problems') ]);
	}
	var items = problems.map(function (p) {
		return E('li', {}, [ T(text(p.interface) + ': ' + text(p.error)) ]);
	});
	return E('ul', {}, [].concat(items));
}

function sandboxText(sb) {
	if (!sb) {
		return _('unknown');
	}
	return lookup(sandboxLabels(), sb.state, _('unknown')) + ' (' +
		'no_new_privs: ' + yesNo(sb.no_new_privs) + ', ' +
		'seccomp: ' + yesNo(sb.seccomp) + ', ' +
		'jail: ' + yesNo(sb.jail) + ')';
}

/* The age past which the group key should have been replaced: its rotation
 * period, 30 days unless the report says otherwise. */
function keyAgeLimit(gk) {
	return (gk && typeof gk.rotates_every_days === 'number' && gk.rotates_every_days > 0) ? gk.rotates_every_days : 30;
}

/* A key older than its rotation period means rotation has stopped somewhere. */
function keyTooOld(gk) {
	return !!gk && typeof gk.age_days === 'number' && gk.age_days > keyAgeLimit(gk);
}

function groupKeyText(gk) {
	if (!gk) {
		return _('no group key yet');
	}
	return _('created') + ' ' + text(gk.created) + ', ' + text(gk.age_days) + ' ' +
		_('days old') + '; ' + _('rotates every') + ' ' + text(gk.rotates_every_days) + ' ' + _('days');
}

function telegramText(tg) {
	if (!tg) {
		return _('unknown');
	}
	var label = lookup(telegramLabels(), tg.state, text(tg.state));
	if (tg.last_ok) {
		label = label + '; ' + _('last successful call') + ' ' + tg.last_ok;
	}
	return label;
}

/* The line for a confirmation of a takeover made on this router (security
 * spec 6.1), or null when there is none: held until the replaced primary has
 * been silent for a day, or lapsed because it was heard before. */
function confirmationText(conf) {
	if (!conf || typeof conf !== 'object') {
		return null;
	}
	if (conf.state === 'held') {
		var of = conf.of ? String(conf.of) : _('the former primary');
		return _('Confirmation of the takeover waits until %s, a day after %s was last heard; it lapses if %s is heard before.')
			.format(text(conf.from), of, of);
	}
	if (conf.state === 'lapsed') {
		return _('Confirmation of the takeover lapsed: the former primary was heard, or the takeover ended, before a day of silence.');
	}
	return null;
}

function buildPage(st) {
	var nodes = [];

	if (st.problem) {
		nodes.push(alertBox('warning', [ T(st.problem) ]));
		return nodes;
	}

	if (st.running === false) {
		nodes.push(alertBox('warning', [
			E('p', {}, [ _('rollcall is not running on this router.') ]),
			E('p', {}, [ T(text(st.error)) ])
		]));
		return nodes;
	}

	if (st.initialised === false) {
		nodes.push(alertBox('warning', [
			_('rollcall is not set up on this router yet. Run rollcall init on the first router, or rollcall join on the others.')
		]));
		return nodes;
	}

	var storageFailed = !!(st.storage && st.storage.ok === false);
	if (storageFailed) {
		nodes.push(alertBox('error', [
			E('strong', {}, [ _('Storage error: ') ]),
			T(text(st.storage.error)),
			E('p', {}, [ _('History stays in RAM until the flash write works again. Copies on the other routers cover this one if it loses power.') ])
		]));
	}

	var flooded = st.under_flood === true;
	if (flooded) {
		nodes.push(alertBox('warning', [
			E('strong', {}, [ _('Under a flood: ') ]),
			_('many packets that fail authentication are arriving at this router. They are dropped and no address is blocked. Members may look silent while it lasts; that is reported as an alarm, never hidden.')
		]));
	}

	var keyOld = keyTooOld(st.group_key);
	if (keyOld) {
		nodes.push(alertBox('warning', [
			E('strong', {}, [ _('Old group key: ') ]),
			T(_('the group key is %s days old; it should have been replaced after %s days. Rotation may have stopped: press Rotate on the Admin tab, and check that every router is up.').format(st.group_key.age_days, keyAgeLimit(st.group_key)))
		]));
	}

	var tg = st.telegram || {};
	if (tg.state === 'bot_blocked' || tg.state === 'tls_failed' || tg.state === 'rate_limited') {
		nodes.push(alertBox('warning', [ T(lookup(telegramLabels(), tg.state, text(tg.state))) ]));
	}

	var self = st.self || {};
	var selfRoles = Array.isArray(self.roles) ? roleNames(self.roles) : [];

	var selfRows = [
		labelRow(_('Name'), [ T(text(self.name)) ]),
		labelRow(_('Roles'), [ T(selfRoles.length ? selfRoles.join(', ') : _('member')) ])
	];
	var confirmation = confirmationText(st.confirmation);
	if (confirmation) {
		selfRows.push(labelRow(_('Takeover'), [ T(confirmation) ]));
	}

	nodes.push(E('h3', {}, [ _('This router') ]));
	nodes.push(E('table', { 'class': 'table' }, [].concat(selfRows)));

	nodes.push(E('h3', {}, [ _('Group') ]));
	nodes.push(E('table', { 'class': 'table' }, [
		labelRow(_('Site'), [ T(text(st.site)) ]),
		labelRow(_('Sender now'), [ T(st.sender ? String(st.sender) : _('none: no member can reach Telegram right now')) ]),
		labelRow(_('Topology'), [ T(lookup(topologyLabels(), st.topology, _('unknown topology'))) ]),
		labelRow(_('Telegram from this router'), [ T(telegramText(tg)) ]),
		labelRow(_('Sandbox'), [ T(sandboxText(st.sandbox)) ]),
		labelRow(_('Storage'), [ T(storageFailed ? _('error, see above') : _('ok')) ]),
		labelRow(_('Flood of bad packets'), [ T(flooded ? _('yes, see above') : _('no')) ]),
		labelRow(_('Group key'), [ keyOld ? E('strong', {}, [ T(groupKeyText(st.group_key)) ]) : T(groupKeyText(st.group_key)) ]),
		labelRow(_('Discovery errors'), [ discoveryNode(st) ]),
		labelRow(_('Report generated'), [ T(text(st.generated)) ])
	]));

	nodes.push(E('h3', {}, [ _('Routers') ]));
	nodes.push(memberTable(st));

	nodes.push(E('h3', {}, [ _('Recent reports') ]));
	nodes.push(incidentTable(st));

	return nodes;
}

function pageContent(st) {
	return [ E('h2', {}, [ _('rollcall status') ]) ].concat(buildPage(st));
}

return view.extend({
	load: function () {
		return loadStatus();
	},

	render: function (st) {
		var box = E('div', { 'class': 'cbi-map' });
		dom.content(box, pageContent(st));

		poll.add(function () {
			return loadStatus().then(function (fresh) {
				dom.content(box, pageContent(fresh));
			});
		}, REFRESH_SECONDS);

		return box;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
