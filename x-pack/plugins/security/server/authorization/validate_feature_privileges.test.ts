/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { Feature } from '../../../features/server';
import { Actions } from './actions';
import { validateFeaturePrivileges } from './validate_feature_privileges';

const actions = new Actions('1.0.0-zeta1');

it(`doesn't allow read to grant privileges which aren't also included in all`, () => {
  const feature: Feature = {
    id: 'foo',
    name: 'foo',
    app: [],
    privileges: {
      all: {
        savedObject: {
          all: ['foo'],
          read: ['bar'],
        },
        ui: [],
      },
      read: {
        savedObject: {
          all: ['foo'],
          read: ['bar', 'baz'],
        },
        ui: [],
      },
    },
  };

  expect(() => validateFeaturePrivileges(actions, [feature])).toThrowErrorMatchingInlineSnapshot(
    `"foo's \\"all\\" privilege should be a superset of the \\"read\\" privilege."`
  );
});

it(`allows all and read to grant the same privileges`, () => {
  const feature: Feature = {
    id: 'foo',
    name: 'foo',
    app: [],
    privileges: {
      all: {
        savedObject: {
          all: ['foo'],
          read: ['bar'],
        },
        ui: [],
      },
      read: {
        savedObject: {
          all: ['foo'],
          read: ['bar'],
        },
        ui: [],
      },
    },
  };

  validateFeaturePrivileges(actions, [feature]);
});

it(`allows all to grant privileges in addition to read`, () => {
  const feature: Feature = {
    id: 'foo',
    name: 'foo',
    app: [],
    privileges: {
      all: {
        savedObject: {
          all: ['foo'],
          read: ['bar', 'baz'],
        },
        ui: [],
      },
      read: {
        savedObject: {
          all: ['foo'],
          read: ['bar'],
        },
        ui: [],
      },
    },
  };

  validateFeaturePrivileges(actions, [feature]);
});
