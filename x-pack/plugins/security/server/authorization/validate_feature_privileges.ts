/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { Feature } from '../../../features/server';
import { Actions } from './actions';
import { featurePrivilegeBuilderFactory } from './privileges/feature_privilege_builder';
import { areActionsFullyCovered } from '../../../../legacy/plugins/security/common/privilege_calculator_utils';

export function validateFeaturePrivileges(actions: Actions, features: Feature[]) {
  const featurePrivilegeBuilder = featurePrivilegeBuilderFactory(actions);
  for (const feature of features) {
    if (feature.privileges.all != null && feature.privileges.read != null) {
      const allActions = featurePrivilegeBuilder.getActions(feature.privileges.all, feature);
      const readActions = featurePrivilegeBuilder.getActions(feature.privileges.read, feature);
      if (!areActionsFullyCovered(allActions, readActions)) {
        throw new Error(
          `${feature.id}'s "all" privilege should be a superset of the "read" privilege.`
        );
      }
    }
  }
}
