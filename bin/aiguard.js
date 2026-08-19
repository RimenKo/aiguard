#!/usr/bin/env node
'use strict';

// Deprecated CLI entry. The public command is `leakward`; `aiguard` stays
// as a compatibility alias so existing hooks and `npm i @rimenko-dev/aiguard`
// keep working. Both package.json bin names also point at leakward.js —
// this file remains so tests and anyone invoking the old path still run.
require('./leakward.js');
