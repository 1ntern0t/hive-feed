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

function keygen(dir, name) {
  const p = join(dir, name);
  const r = run(['keygen', '--out', p]);
  assert.equal(r.status, 0, r.stderr);
  return { path: p, pub: r.stdout.match(/public_key (\S+)/)[1] };
}

test('CLI init prints the anchor fingerprint; verify needs a trust source and checks it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hive-cli-anchor-'));
  const k = keygen(dir, 'throwaway-test.key');
  const feed = join(dir, 'feed.json');
  const init = run(['init', '--feed', feed, '--key', k.path, '--feed-id', 'cli-anchor']);
  assert.equal(init.status, 0, init.stderr);
  const anchor = init.stdout.match(/^anchor (hf2:(?:[0-9a-f]{4}-){7}[0-9a-f]{4})$/m)[1];
  assert.match(init.stdout, /^anchor_full [0-9a-f]{64}$/m);
  assert.equal(run(['append', '--feed', feed, '--key', k.path, '--type', 'task', '--id', 'e1', '--channel', 'c', '--poster', 'U-GIGATRON', '--text', 'hi']).status, 0);
  const fp = run(['fingerprint', '--feed', feed]);
  assert.equal(fp.status, 0, fp.stderr);
  assert.ok(fp.stdout.includes('anchor ' + anchor));

  const ok = run(['verify', '--feed', feed, '--anchor', anchor, '--trusted', 'U-GIGATRON']);
  assert.equal(ok.status, 0, ok.stderr);
  assert.ok(ok.stderr.includes('OK feed cli-anchor anchor ' + anchor));

  const none = run(['verify', '--feed', feed]);
  assert.equal(none.status, 2);
  assert.match(none.stderr, /refusing to verify without a trust anchor/);

  const wrong = run(['verify', '--feed', feed, '--anchor', 'hf2:' + '0'.repeat(32)]);
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /HIVE_ANCHOR_MISMATCH/);

  const tofu = run(['verify', '--feed', feed, '--unpinned-tofu']);
  assert.equal(tofu.status, 0, tofu.stderr);
  assert.match(tofu.stderr, /WARNING: UNPINNED/);
  assert.match(tofu.stderr, /UNPINNED-OK feed cli-anchor anchor hf2:/);

  const both = run(['verify', '--feed', feed, '--anchor', anchor, '--unpinned-tofu']);
  assert.equal(both.status, 2);
});

test('CLI rotate and recover keep the anchor; old key is refused afterwards', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hive-cli-rot-'));
  const k0 = keygen(dir, 'throwaway-k0.key');
  const k1 = keygen(dir, 'throwaway-k1.key');
  const k2 = keygen(dir, 'throwaway-k2.key');
  const rec = keygen(dir, 'throwaway-recovery.key');
  const feed = join(dir, 'feed.json');
  const init = run(['init', '--feed', feed, '--key', k0.path, '--feed-id', 'cli-rot', '--recovery-pubkey', rec.pub]);
  assert.equal(init.status, 0, init.stderr);
  const anchor = init.stdout.match(/^anchor (\S+)$/m)[1];
  const ev = (key, id) => run(['append', '--feed', feed, '--key', key, '--type', 'task', '--id', id, '--channel', 'c', '--poster', 'U-GIGATRON', '--text', id]);
  assert.equal(ev(k0.path, 'e1').status, 0);

  const rot = run(['rotate', '--feed', feed, '--key', k0.path, '--next-key', k1.path, '--id', 'rot-1', '--grace-events', '1']);
  assert.equal(rot.status, 0, rot.stderr);
  assert.ok(rot.stdout.includes('anchor ' + anchor));
  assert.equal(ev(k1.path, 'e3').status, 0);
  const old = ev(k0.path, 'e4');
  assert.equal(old.status, 2);
  assert.match(old.stderr, /not the current publisher key/);

  const recv = run(['recover', '--feed', feed, '--recovery-key', rec.path, '--next-key', k2.path, '--id', 'recover-1']);
  assert.equal(recv.status, 0, recv.stderr);
  assert.match(recv.stdout, /recovered at seq 4/);
  assert.equal(ev(k2.path, 'e5').status, 0);

  const v = run(['verify', '--feed', feed, '--anchor', anchor, '--trusted', 'U-GIGATRON,publisher']);
  assert.equal(v.status, 0, v.stderr);
  assert.match(v.stderr, /rotations 2 head seq 5/);
  const wrongRec = run(['recover', '--feed', feed, '--recovery-key', k0.path, '--next-key', keygen(dir, 'throwaway-k3.key').path, '--id', 'recover-2']);
  assert.equal(wrongRec.status, 1);
  assert.match(wrongRec.stderr, /HIVE_BAD_ROTATION/);
});
