import { schema } from '../..';

test('handles object as input', () => {
  const type = schema.mapOf(schema.string(), schema.string());
  const value = {
    name: 'foo',
  };
  const expected = new Map([['name', 'foo']]);

  expect(type.validate(value)).toEqual(expected);
});

test('fails when not receiving expected value type', () => {
  const type = schema.mapOf(schema.string(), schema.string());
  const value = {
    name: 123,
  };

  expect(() => type.validate(value)).toThrowErrorMatchingSnapshot();
});

test('fails when not receiving expected key type', () => {
  const type = schema.mapOf(schema.number(), schema.string());
  const value = {
    name: 'foo',
  };

  expect(() => type.validate(value)).toThrowErrorMatchingSnapshot();
});

test('includes context in failure when wrong top-level type', () => {
  const type = schema.mapOf(schema.string(), schema.string());
  expect(() => type.validate([], 'foo-context')).toThrowErrorMatchingSnapshot();
});

test('includes context in failure when wrong value type', () => {
  const type = schema.mapOf(schema.string(), schema.string());
  const value = {
    name: 123,
  };

  expect(() =>
    type.validate(value, 'foo-context')
  ).toThrowErrorMatchingSnapshot();
});

test('includes context in failure when wrong key type', () => {
  const type = schema.mapOf(schema.number(), schema.string());
  const value = {
    name: 'foo',
  };

  expect(() =>
    type.validate(value, 'foo-context')
  ).toThrowErrorMatchingSnapshot();
});

test('returns default value if undefined', () => {
  const obj = new Map([['foo', 'bar']]);

  const type = schema.mapOf(schema.string(), schema.string(), {
    defaultValue: obj,
  });

  expect(type.validate(undefined)).toEqual(obj);
});

test('mapOf within mapOf', () => {
  const type = schema.mapOf(
    schema.string(),
    schema.mapOf(schema.string(), schema.number())
  );
  const value = {
    foo: {
      bar: 123,
    },
  };
  const expected = new Map([['foo', new Map([['bar', 123]])]]);

  expect(type.validate(value)).toEqual(expected);
});

test('object within mapOf', () => {
  const type = schema.mapOf(
    schema.string(),
    schema.object({
      bar: schema.number(),
    })
  );
  const value = {
    foo: {
      bar: 123,
    },
  };
  const expected = new Map([['foo', { bar: 123 }]]);

  expect(type.validate(value)).toEqual(expected);
});
