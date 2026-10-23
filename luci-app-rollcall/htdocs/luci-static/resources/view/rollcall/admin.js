'use strict';
'require view';
'require dom';
'require rpc';
'require ui';

/*
 * Admin page: the changes only an admin router may make. Inviting a router,
 * removing one, setting roles, rotating the group key, binding the Telegram
 * chat and setting the bot token, plus the takeover steps for a backup admin.
 *
 * Every write goes through `rollcall <command> ... --json`, and rpcd allows
 * only the command forms listed in the luci-app-rollcall-admin ACL group. The
 * reply is one JSON object (see luci-app-rollcall/STATUS-JSON.md). A join code
 * or a bind code in that reply is shown to the admin in a dialog and nowhere
 * else: it is not stored, logged or sent.
 *
 * Every value reaches the page as a text node: E() gets its children as an
 * array or an element, and each value is wrapped in T().
 */

var ROLLCALL = '/usr/bin/rollcall';
var SCHEMA = 1;

var callExec = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ]
});

var callExecEnv = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params', 'env' ]
});

/* A text node holding s. Every value from the daemon goes through here. */
function T(s) {
	return document.createTextNode(String(s == null ? '' : s));
}

function text(v, fallback) {
	return String((v === null || v === undefined || v === '') ? (fallback || '-') : v);
}

/* Reads the status report, as the status page does. */
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

/* Turns the reply of an admin command into { ok, message, error, join_code, bind_code }. */
function parseResult(res) {
	var r;
	try {
		r = JSON.parse((res && res.stdout) || '');
	} catch (e) {
		r = null;
	}
	if (!r || typeof r !== 'object') {
		return { ok: false, error: _('rollcall gave no result.') };
	}
	return r;
}

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

function hasKey(table, key) {
	return typeof key === 'string' && Object.prototype.hasOwnProperty.call(table, key);
}

function lookup(table, key, fallback) {
	return hasKey(table, key) ? table[key] : fallback;
}

/* label is a translated literal or a text; children is an array of nodes. */
function button(label, cls, onClick) {
	return E('button', { 'class': 'cbi-button ' + cls, 'click': onClick }, [ T(label) ]);
}

function alertBox(severity, children) {
	return E('div', { 'class': 'alert-message ' + severity }, [].concat(children));
}

/* Runs one admin command and shows its reply in a dialog. Resolves with the reply. */
function runAdmin(args, env, title) {
	var call = env ? callExecEnv(ROLLCALL, args, env) : callExec(ROLLCALL, args);
	ui.showModal(title, [ E('p', { 'class': 'spinning' }, [ _('Working...') ]) ]);
	return call.then(function (res) {
		return parseResult(res);
	}, function () {
		return { ok: false, error: _('rollcall could not be run. Is this login allowed to administer rollcall?') };
	}).then(function (result) {
		showResult(title, result);
		return result;
	});
}

function showResult(title, result) {
	var body = [];
	if (result.ok === true) {
		body.push(E('p', {}, [ T(text(result.message, _('Done.'))) ]));
	} else {
		body.push(alertBox('error', [ T(text(result.error, _('Failed.'))) ]));
	}
	if (result.join_code) {
		body.push(E('p', {}, [ _('Join code. It works once, for 10 minutes. Enter it on the new router with rollcall join. It is shown only here.') ]));
		body.push(E('p', {}, [ E('code', {}, [ T(result.join_code) ]) ]));
	}
	if (result.bind_code) {
		body.push(E('p', {}, [ _('Send this code to the rollcall bot in a private chat within 10 minutes. It is shown only here.') ]));
		body.push(E('p', {}, [ E('code', {}, [ T(result.bind_code) ]) ]));
	}
	body.push(E('div', { 'class': 'right' }, [
		button(_('Close'), '', ui.hideModal)
	]));
	ui.showModal(title, body);
}

/* A dialog that runs the action only when the admin presses the named button.
 * question is a text (it may name a router, so it is never passed as markup). */
function confirmThen(title, question, label, action) {
	ui.showModal(title, [
		E('p', {}, [ T(question) ]),
		E('div', { 'class': 'right' }, [
			button(_('Cancel'), '', ui.hideModal),
			' ',
			button(label, 'cbi-button-negative', function () {
				ui.hideModal();
				return action();
			})
		])
	]);
}

function backupWarning() {
	return alertBox('warning', [
		E('strong', {}, [ _('Warning: ') ]),
		_('A system backup contains rollcall\'s secrets; treat it like a password; after sharing one, press Rotate.')
	]);
}

function selfTable(st) {
	var self = st.self || {};
	var adminRole = lookup({ primary: _('primary admin'), backup: _('backup admin') }, self.admin, _('not an admin'));
	var rows = [
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'style': 'width:28%' }, [ _('Name') ]),
			E('td', { 'class': 'td left' }, [ T(text(self.name)) ])
		]),
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'style': 'width:28%' }, [ _('Admin role') ]),
			E('td', { 'class': 'td left' }, [ T(adminRole) ])
		])
	];
	if (self.takeover === true) {
		rows.push(E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'style': 'width:28%' }, [ _('Takeover') ]),
			E('td', { 'class': 'td left' }, [ _('provisional: waiting for confirmation') ])
		]));
	}
	return E('table', { 'class': 'table' }, [].concat(rows));
}

/* The invite dialog: the sender role (security design 6, join step 3: only
 * when the owner ticks it) and the address the new router reaches this one
 * at, which the CLI checks. They reach the CLI as its own flags, in the forms
 * of the ACL: invite --json [--sender] [-- <address>]. */
function inviteDialog(reload) {
	var sender = E('input', { 'type': 'checkbox', 'id': 'rollcall-invite-sender' });
	var address = E('input', {
		'type': 'text',
		'id': 'rollcall-invite-address',
		'class': 'cbi-input-text',
		'autocomplete': 'off',
		'spellcheck': 'false',
		'placeholder': _('an address of this router')
	});
	ui.showModal(_('Invite a router'), [
		E('p', {}, [ _('Opens a join window for 10 minutes and shows a join code that works once.') ]),
		E('p', {}, [
			E('label', {}, [ sender, ' ', _('The new router sends to Telegram (sender role)') ])
		]),
		E('p', {}, [
			E('label', { 'for': 'rollcall-invite-address' }, [ _('Address the new router reaches this router at') ]),
			E('br'),
			address
		]),
		E('p', {}, [ _('Leave it empty to use the first address of this router\'s peer zones. Give one when the new router reaches this router at another address, for example across sites over WireGuard or Tailscale.') ]),
		E('div', { 'class': 'right' }, [
			button(_('Cancel'), '', ui.hideModal),
			' ',
			button(_('Open join window'), 'cbi-button-action', function () {
				var args = [ 'invite', '--json' ];
				if (sender.checked) {
					args.push('--sender');
				}
				var addr = String(address.value || '').trim();
				if (addr) {
					args.push('--', addr);
				}
				return runAdmin(args, null, _('Invite a router')).then(reload);
			})
		])
	]);
}

function actionRow(st, reload) {
	var self = st.self || {};
	var buttons = [
		button(_('Invite a router'), 'cbi-button-action', function () {
			return inviteDialog(reload);
		}),
		button(_('Rotate'), 'cbi-button-action', function () {
			return confirmThen(_('Rotate the group key'),
				_('Every router gets a new group key now. Routers that are away must join again.'),
				_('Rotate'),
				function () {
					return runAdmin([ 'rotate', '--json' ], null, _('Rotate the group key')).then(reload);
				});
		}),
		button(_('Bind Telegram chat'), 'cbi-button-action', function () {
			return runAdmin([ 'bind-telegram', '--json' ], null, _('Bind Telegram chat')).then(reload);
		})
	];

	if (self.admin === 'backup') {
		buttons.push(button(_('Take over as primary'), 'cbi-button-negative', function () {
			return confirmThen(_('Take over as primary'),
				_('Use this only when the primary admin is gone. A takeover is provisional: if the old primary comes back, it takes the role back until this takeover is confirmed here.'),
				_('Take over'),
				function () {
					return runAdmin([ 'admin', 'takeover', '--json' ], null, _('Take over as primary')).then(reload);
				});
		}));
	}

	if (self.takeover === true) {
		buttons.push(button(_('Confirm takeover'), 'cbi-button-apply', function () {
			return confirmThen(_('Confirm the takeover'),
				_('Confirm this takeover? The old primary will then no longer take the role back.'),
				_('Confirm'),
				function () {
					return runAdmin([ 'admin', 'confirm', '--json' ], null, _('Confirm the takeover')).then(reload);
				});
		}));
	}

	var children = [];
	buttons.forEach(function (b, i) {
		if (i > 0) {
			children.push(' ');
		}
		children.push(b);
	});
	return E('div', { 'class': 'cbi-page-actions' }, [].concat(children));
}

function membersTable(st, reload) {
	var self = st.self || {};
	var members = Array.isArray(st.members) ? st.members : [];
	if (!members.length) {
		return E('p', {}, [ _('No members are known yet.') ]);
	}
	var roles = roleLabels();
	var states = memberStateLabels();

	var head = E('tr', { 'class': 'tr table-titles' }, [
		E('th', { 'class': 'th' }, [ _('Router') ]),
		E('th', { 'class': 'th' }, [ _('Roles') ]),
		E('th', { 'class': 'th' }, [ _('State') ]),
		E('th', { 'class': 'th' }, [ _('Change') ])
	]);

	var rows = members.map(function (m) {
		var name = text(m.name);
		var memberRoles = Array.isArray(m.roles) ? m.roles : [];
		var roleText = memberRoles.length
			? memberRoles.map(function (r) { return lookup(roles, r, String(r)); }).join(', ')
			: _('member');
		var cells = [
			E('td', { 'class': 'td left' }, [ T(name) ]),
			E('td', { 'class': 'td left' }, [ T(roleText) ]),
			E('td', { 'class': 'td left' }, [ T(lookup(states, m.state, text(m.state))) ])
		];

		if (self.name && m.name === self.name) {
			cells.push(E('td', { 'class': 'td left' }, [ _('this router') ]));
			return E('tr', { 'class': 'tr' }, [].concat(cells));
		}

		var select = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': '' }, [ _('choose a role') ]),
			E('option', { 'value': 'none' }, [ _('member') ]),
			E('option', { 'value': 'sender' }, [ _('sends to Telegram') ]),
			E('option', { 'value': 'primary' }, [ _('primary admin') ]),
			E('option', { 'value': 'backup' }, [ _('backup admin') ])
		]);

		cells.push(E('td', { 'class': 'td left' }, [
			select,
			' ',
			button(_('Set role'), 'cbi-button-apply', function () {
				var role = select.value;
				if (!role) {
					ui.addNotification(null, E('p', {}, [ _('Choose a role first.') ]), 'danger');
					return null;
				}
				return confirmThen(_('Change a role'),
					_('Change the role of %s to %s? Roster changes are announced in the chat.').format(name, role),
					_('Change role'),
					function () {
						return runAdmin([ 'roles', '--json', role, '--', name ], null, _('Change a role')).then(reload);
					});
			}),
			' ',
			button(_('Remove'), 'cbi-button-negative', function () {
				return confirmThen(_('Remove a router'),
					_('Remove %s from the group? It loses the group key at once. If it sent to Telegram, revoke the bot token in BotFather and set the new one on the Admin page.').format(name),
					_('Remove'),
					function () {
						return runAdmin([ 'remove', '--json', '--', name ], null, _('Remove a router')).then(reload);
					});
			})
		]));

		return E('tr', { 'class': 'tr' }, [].concat(cells));
	});

	return E('table', { 'class': 'table' }, [ head ].concat(rows));
}

function tokenForm(reload) {
	var input = E('input', {
		'type': 'password',
		'class': 'cbi-input-password',
		'autocomplete': 'off',
		'spellcheck': 'false',
		'placeholder': _('bot token from BotFather')
	});

	return E('div', {}, [
		E('h3', {}, [ _('Telegram bot token') ]),
		E('p', {}, [ _('Set the token only on a router that sends to Telegram. If the old token may have leaked, revoke it in BotFather first, then set the new one here. The token is not shown again after it is set.') ]),
		E('div', {}, [
			input,
			' ',
			button(_('Set token'), 'cbi-button-apply', function () {
				var value = input.value;
				input.value = '';
				if (!value) {
					ui.addNotification(null, E('p', {}, [ _('Enter the token first.') ]), 'danger');
					return null;
				}
				return runAdmin([ 'set-token', '--json' ], { 'TELEGRAM_ROLLCALL_TOKEN': value },
					_('Set the Telegram token')).then(reload);
			})
		])
	]);
}

function pageContent(st, reload) {
	var nodes = [
		E('h2', {}, [ _('rollcall admin') ]),
		E('div', { 'class': 'cbi-page-actions' }, [
			button(_('Refresh'), 'cbi-button', reload)
		])
	];

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

	if (st.backup_warning) {
		nodes.push(backupWarning());
	}

	nodes.push(E('h3', {}, [ _('This router') ]));
	nodes.push(selfTable(st));
	nodes.push(actionRow(st, reload));

	nodes.push(E('h3', {}, [ _('Routers') ]));
	nodes.push(membersTable(st, reload));

	nodes.push(tokenForm(reload));

	return nodes;
}

function reloadInto(box) {
	return loadStatus().then(function (st) {
		dom.content(box, pageContent(st, function () {
			return reloadInto(box);
		}));
	});
}

return view.extend({
	load: function () {
		return loadStatus();
	},

	render: function (st) {
		var box = E('div', { 'class': 'cbi-map' });
		dom.content(box, pageContent(st, function () {
			return reloadInto(box);
		}));
		return box;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
