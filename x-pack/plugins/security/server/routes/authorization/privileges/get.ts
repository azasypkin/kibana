/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
import { schema } from '@kbn/config-schema';
import { RouteDefinitionParams } from '../..';
import { createLicensedRouteHandler } from '../../licensed_route_handler';

export function defineGetPrivilegesRoutes({ router, authz }: RouteDefinitionParams) {
  router.get(
    {
      path: '/api/security/privileges',
      validate: {
        query: schema.object({ includeActions: schema.boolean({ defaultValue: false }) }),
      },
    },
    createLicensedRouteHandler((context, request, response) => {
      const privileges = authz.privileges.get();
      const privilegesResponseBody = request.query.includeActions
        ? privileges
        : {
            global: Object.keys(privileges.global),
            space: Object.keys(privileges.space),
            features: Object.entries(privileges.features).reduce(
              (acc, [featureId, featurePrivileges]) => {
                return {
                  ...acc,
                  [featureId]: Object.keys(featurePrivileges),
                };
              },
              {}
            ),
            reserved: Object.keys(privileges.reserved),
          };

      return response.ok({ body: privilegesResponseBody });
    })
  );
}
