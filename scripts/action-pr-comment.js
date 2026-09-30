#!/usr/bin/env node
// Posts or updates the ContextHound summary comment on a pull request.
// Run by action.yml; every input arrives through the environment.
//
//   GITHUB_TOKEN      token with pull-requests: write
//   HOUND_PKG         directory of the installed context-hound package
//   HOUND_RESULTS     JSON report written by the scan
//   HOUND_DIFF_REF    ref the scan was limited to (optional)
//   GITHUB_EVENT_PATH, GITHUB_REPOSITORY, GITHUB_API_URL, GITHUB_SERVER_URL
//
// A failure to comment (for example the read-only token of a fork pull
// request) is reported as a warning and never fails the job.
'use strict';

const fs = require('fs');
const path = require('path');

const BOT_LOGIN = 'github-actions[bot]';

function warn(message) {
  console.log(`::warning::${String(message).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')}`);
}

async function request(api, token, method, url, body) {
  const res = await fetch(`${api}${url}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      ...(body && { 'content-type': 'application/json' }),
    },
    ...(body && { body: JSON.stringify(body) }),
  });
  if (!res.ok) throw new Error(`${method} ${url} failed: ${res.status} ${res.statusText}`);
  return res.status === 204 ? null : res.json();
}

/** The existing ContextHound comment, if this workflow posted one. */
async function findComment(api, token, repo, number, marker) {
  for (let page = 1; page <= 20; page++) {
    const comments = await request(api, token, 'GET', `/repos/${repo}/issues/${number}/comments?per_page=100&page=${page}`);
    const mine = comments.find(c => c.user && c.user.login === BOT_LOGIN && typeof c.body === 'string' && c.body.startsWith(marker));
    if (mine) return mine;
    if (comments.length < 100) return null;
  }
  return null;
}

async function run(env = process.env) {
  const event = JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH, 'utf8'));
  const pr = event.pull_request;
  if (!pr || !Number.isInteger(pr.number)) {
    console.log('Not a pull request event; skipping the comment.');
    return 'skipped';
  }
  const repo = env.GITHUB_REPOSITORY;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo || '')) throw new Error('GITHUB_REPOSITORY is not set');

  const lib = require(path.join(env.HOUND_PKG, 'node_modules', 'context-hound'));
  if (typeof lib.buildPrComment !== 'function') {
    throw new Error('PR comments need a newer context-hound; raise the version input');
  }
  const result = JSON.parse(fs.readFileSync(env.HOUND_RESULTS, 'utf8'));
  const server = (env.GITHUB_SERVER_URL || 'https://github.com').replace(/\/+$/, '');
  const body = lib.buildPrComment(result, {
    blobBaseUrl: `${server}/${repo}/blob/${pr.head.sha}`,
    diffRef: env.HOUND_DIFF_REF || undefined,
  });

  const api = (env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
  const token = env.GITHUB_TOKEN;
  const existing = await findComment(api, token, repo, pr.number, lib.PR_COMMENT_MARKER);
  if (existing) {
    await request(api, token, 'PATCH', `/repos/${repo}/issues/comments/${existing.id}`, { body });
    console.log(`Updated the ContextHound comment on #${pr.number}.`);
    return 'updated';
  }
  await request(api, token, 'POST', `/repos/${repo}/issues/${pr.number}/comments`, { body });
  console.log(`Posted a ContextHound comment on #${pr.number}.`);
  return 'created';
}

module.exports = { run, findComment, BOT_LOGIN };

if (require.main === module) {
  run().catch(err => warn(`Could not comment on the pull request: ${err.message}`));
}
