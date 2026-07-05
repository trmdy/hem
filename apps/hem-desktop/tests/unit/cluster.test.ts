import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  clusterHealthFromOutput,
  parseKvOutput,
  peerConfigFromRecord,
  peerHealthFromRecord,
} from '../../src/main/hem/cluster';

const fixture = (name: string): string => readFileSync(join(__dirname, '..', 'fixtures', name), 'utf8');

describe('parseKvOutput', () => {
  it('splits scalars and record lines', () => {
    const parsed = parseKvOutput('a=1\nb=two words\npeer node_id=n1 endpoint=http://x lag=3\n# comment\n');
    expect(parsed.scalars).toEqual({ a: '1', b: 'two words' });
    expect(parsed.records).toEqual([
      { type: 'peer', fields: { node_id: 'n1', endpoint: 'http://x', lag: '3' } },
    ]);
  });

  it('re-joins values containing spaces onto the previous key', () => {
    const parsed = parseKvOutput('peer_health node_id=n1 error=connection refused by peer');
    expect(parsed.records[0].fields.error).toBe('connection refused by peer');
  });
});

describe('cluster health from captured live output', () => {
  it('parses the 2026-07-04 warning-state fixture', () => {
    const health = clusterHealthFromOutput(fixture('cluster-health.txt'), 1);
    expect(health.status).toBe('warning');
    expect(health.scalars.latest_position).toBe('7882');
    expect(health.scalars.healthy_peers).toBe('4');
    expect(health.peers).toHaveLength(5);
    const elm = health.peers.find((p) => p.nodeId === 'hmn_elm05');
    expect(elm).toMatchObject({ status: 'lagging', lag: 6567, cursorPosition: 1315 });
    expect(elm?.lastSeen).toBe('2026-06-03T08:16:16.779731+00:00');
    expect(elm?.error).toBeNull();
  });

  it('falls back to exit-code mapping when the status scalar is missing', () => {
    expect(clusterHealthFromOutput('', 0).status).toBe('ok');
    expect(clusterHealthFromOutput('', 1).status).toBe('warning');
    expect(clusterHealthFromOutput('', 2).status).toBe('critical');
    expect(clusterHealthFromOutput('', 3).status).toBe('unknown');
  });

  it('unknown peer statuses map to "unknown"', () => {
    const peer = peerHealthFromRecord({ type: 'peer_health', fields: { node_id: 'x', status: 'weird' } });
    expect(peer.status).toBe('unknown');
  });
});

describe('cluster snapshot fixtures', () => {
  it('parses status scalars', () => {
    const parsed = parseKvOutput(fixture('cluster-status.txt'));
    expect(parsed.scalars.cluster_id).toBe('hmc_democluster000000000000000');
    expect(parsed.scalars.node_id).toBe('hmn_main');
    expect(parsed.scalars.quorum).toBe('1');
    expect(parsed.scalars.data_dir).toBe('/home/user/.valhall/system-daemons/data/hem');
  });

  it('parses the five configured peers', () => {
    const parsed = parseKvOutput(fixture('cluster-peers.txt'));
    const peers = parsed.records.filter((r) => r.type === 'peer').map(peerConfigFromRecord);
    expect(peers).toHaveLength(5);
    expect(peers[0]).toMatchObject({ nodeId: 'hmn_alder01', endpoint: 'http://192.0.2.250:50091' });
    expect(peers.every((p) => p.publicKey)).toBe(true);
  });

  it('parses the empty collisions fixture', () => {
    const parsed = parseKvOutput(fixture('cluster-collisions.txt'));
    expect(parsed.scalars.collisions).toBe('0');
    expect(parsed.records.filter((r) => r.type === 'collision')).toHaveLength(0);
  });
});
