import { describe, expect, it } from 'vitest';
import {
  formatRef,
  parseRef,
  protoToRef,
  refToProto,
  scopeSectionKey,
} from '../../src/main/hem/refs';

describe('parseRef', () => {
  it('parses the three explicit forms', () => {
    expect(parseRef('global/anthropic-api-key')).toEqual({ scope: 'global', name: 'anthropic-api-key' });
    expect(parseRef('project/acme/openai-prod')).toEqual({
      scope: 'project',
      project: 'acme',
      name: 'openai-prod',
    });
    expect(parseRef('identity/vis-7f31/github')).toEqual({
      scope: 'identity',
      identityId: 'vis-7f31',
      name: 'github',
    });
  });

  it('rejects bare names — read/write resolution differs, callers must be explicit', () => {
    expect(parseRef('openai-prod')).toBeNull();
  });

  it('rejects invalid slugs and malformed refs', () => {
    expect(parseRef('global/UPPER')).toBeNull();
    expect(parseRef('project/acme')).toBeNull();
    expect(parseRef('project/acme/a/b')).toBeNull();
    expect(parseRef('mystery/acme/x')).toBeNull();
    expect(parseRef('global/has space')).toBeNull();
  });

  it('round-trips through formatRef', () => {
    for (const ref of ['global/a-1', 'project/p/n', 'identity/i/n']) {
      expect(formatRef(parseRef(ref)!)).toBe(ref);
    }
  });
});

describe('proto mapping', () => {
  it('maps to keepCase wire shapes and back', () => {
    const proto = refToProto({ scope: 'project', project: 'acme', name: 'openai-prod' });
    expect(proto).toEqual({
      scope: { scope: 'SECRET_SCOPE_PROJECT', project: 'acme' },
      name: 'openai-prod',
    });
    expect(protoToRef(proto.scope, proto.name)).toEqual({
      scope: 'project',
      project: 'acme',
      name: 'openai-prod',
    });
  });

  it('unknown scope enums default to global on read', () => {
    expect(protoToRef({ scope: 'SECRET_SCOPE_UNSPECIFIED' }, 'x')).toEqual({ scope: 'global', name: 'x' });
    expect(protoToRef(undefined, 'x')).toEqual({ scope: 'global', name: 'x' });
  });

  it('section keys group by container', () => {
    expect(scopeSectionKey({ scope: 'global', name: 'x' })).toBe('global');
    expect(scopeSectionKey({ scope: 'project', project: 'acme', name: 'x' })).toBe('project/acme');
    expect(scopeSectionKey({ scope: 'identity', identityId: 'vis', name: 'x' })).toBe('identity/vis');
  });
});
