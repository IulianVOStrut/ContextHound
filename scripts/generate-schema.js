#!/usr/bin/env node
// Regenerates schema/contexthoundrc.schema.json from src/config/schema.ts.
// Run with `npm run schema`; tests fail if the committed file is stale.
const fs = require('fs');
const path = require('path');
const { buildJsonSchema } = require('../dist/config/schema.js');

const out = path.join(__dirname, '..', 'schema', 'contexthoundrc.schema.json');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(buildJsonSchema(), null, 2) + '\n', 'utf8');
console.log(`Wrote ${path.relative(process.cwd(), out)}`);
