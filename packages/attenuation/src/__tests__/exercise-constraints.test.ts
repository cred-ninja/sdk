import { describe, it, expect } from 'vitest';
import { exerciseConstraintViolation } from '../index.js';

describe('exerciseConstraintViolation', () => {
  it('decides each per-exercise type, failing closed on the wrong kind of value', () => {
    expect(exerciseConstraintViolation({ key: 'max_rows', max: 10 }, 10)).toBeNull();
    expect(exerciseConstraintViolation({ key: 'max_rows', max: 10 }, 11)).toMatch(/exceeds/);
    expect(exerciseConstraintViolation({ key: 'max_rows', max: 10 }, '5')).toMatch(/exceeds/);
    expect(exerciseConstraintViolation({ key: 'n', min: 2 }, 1)).toMatch(/below/);
    expect(exerciseConstraintViolation({ key: 'method', one_of: ['GET'] }, 'GET')).toBeNull();
    expect(exerciseConstraintViolation({ key: 'method', one_of: ['GET'] }, 'DELETE')).toMatch(/not one of/);
    expect(exerciseConstraintViolation({ key: 'method', not_one_of: ['DELETE'] }, 'DELETE')).toMatch(/refused/);
    expect(exerciseConstraintViolation({ key: 'method', not_one_of: ['DELETE'] }, undefined)).toMatch(/refused/);
    expect(exerciseConstraintViolation({ key: 'destination', prefix: 'https://api.github.com/repos/acme/' }, 'https://api.github.com/repos/acme/app')).toBeNull();
    expect(exerciseConstraintViolation({ key: 'destination', prefix: 'https://api.github.com/repos/acme/' }, 'https://api.github.com/repos/other')).toMatch(/prefix/);
  });

  it('compares ranks numerically or through the ordering', () => {
    expect(exerciseConstraintViolation({ key: 'tier', rank: 2 }, 2)).toBeNull();
    expect(exerciseConstraintViolation({ key: 'tier', rank: 2 }, 3)).toMatch(/above/);
    const egress = { key: 'egress', rank: 'internal', order: ['none', 'internal', 'any'] };
    expect(exerciseConstraintViolation(egress, 'none')).toBeNull();
    expect(exerciseConstraintViolation(egress, 'any')).toMatch(/above/);
    expect(exerciseConstraintViolation(egress, 'unknown')).toMatch(/above/);
    expect(exerciseConstraintViolation({ key: 'egress', rank: 'internal' }, 'internal')).toBeNull();
  });

  it('refuses cumulative and unknown types, which are not decided per exercise', () => {
    expect(exerciseConstraintViolation({ key: 'max_calls', max_lifetime: 3 }, 1)).toMatch(/not decided per exercise/);
    expect(exerciseConstraintViolation({ key: 'x', future: 1 }, 1)).toMatch(/not decided per exercise/);
  });
});
