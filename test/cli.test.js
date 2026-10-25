import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, statSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CLI = ['bin/hive-feed.js'];
function run(args, opts = {}) {
  return spawnSync(process.execPath, [...CLI, ...args], { encoding: 'utf8', ...opts });
}

test('keygen writes 0600 key outside repo and prints only the public key', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hive-cli-'));
  const keyPath = join(dir, 'throwaway-test.key');
  const r = run(['keygen', '--out', keyPath]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^public_key [A-Za-z0-9+/]{43}=\nkey_id [0-9a-f]{16}\n$/);
  assert.ok(!/PRIVATE/.test(r.stdout + r.stderr));
  assert.equal(statSync(keyPath).mode & 0o777, 0o600);
  assert.match(readFileSync(keyPath, 'utf8'), /BEGIN PRIVATE KEY/);
  const again = run(['keygen', '--out', keyPath]);
  assert.notEqual(again.status, 0, 'must not overwrite an existing key');
});

test('keygen refuses to write inside a git work tree', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hive-cli-git-'));
  mkdirSync(join(dir, '.git'));
  const r = run(['keygen', '--out', join(dir, 'sub.key')]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /git work tree/);
  assert.equal(existsSync(join(dir, 'sub.key')), false);
});

test('append + verify round trip, then tamper detection via CLI', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hive-cli-rt-'));
  const keyPath = join(dir, 'throwaway-test.key');
  const pub = run(['keygen', '--out', keyPath]).stdout.match(/public_key (\S+)/)[1];
  const feed = join(dir, 'feed.json');
  for (const [i, type] of [[1, 'task'], [2, 'speed_ping'], [3, 'result']]) {
    const r = run(['append', '--feed', feed, '--key', keyPath, '--feed-id', 'cli-test', '--type', type, '--id', 'e' + i,
      '--channel', 'build', '--poster', 'U-GIGATRON', '--url', 'https://example.org/' + i, '--text', 'hello ' + i]);
    assert.equal(r.status, 0, r.stderr);
  }
  const v = run(['verify', '--feed', feed, '--pubkey', pub, '--trusted', 'U-GIGATRON']);
  assert.equal(v.status, 0, v.stderr);
  assert.match(v.stderr, /OK feed cli-test .* head seq 3/);
  assert.equal(v.stdout.trim().split('\n').length, 3);

  const bad = run(['append', '--feed', feed, '--key', keyPath, '--type', 'exec', '--id', 'z', '--channel', 'c', '--poster', 'p', '--text', 'x']);
  assert.notEqual(bad.status, 0);

  const raw = readFileSync(feed, 'utf8').replace('hello 2', 'HELLO 2');
  const f2 = join(dir, 'tampered.json');
  spawnSync('cp', [feed + '.sig', f2 + '.sig']);
  spawnSync('sh', ['-c', 'cat > "$1"', 'sh', f2], { input: raw });
  const t = run(['verify', '--feed', f2, '--pubkey', pub]);
  assert.equal(t.status, 1);
  assert.match(t.stderr, /HIVE_BAD_SIGNATURE/);
});
