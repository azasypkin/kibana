/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { resolve } from 'path';
import { Server } from 'src/legacy/server/kbn_server';
import { SecurityPluginSetup } from '../../../plugins/security/server';

export const security = (kibana: Record<string, any>) =>
  new kibana.Plugin({
    id: 'security',
    publicDir: resolve(__dirname, 'public'),
    require: ['kibana', 'xpack_main'],

    uiExports: { hacks: ['plugins/security/hacks/legacy'] },

    async init(server: Server) {
      const securityPlugin = server.newPlatform.setup.plugins.security as SecurityPluginSetup;
      if (!securityPlugin) {
        throw new Error('Kibana Platform Security plugin is not available.');
      }

      // Legacy xPack Info endpoint returns whatever we return in a callback for `registerLicenseCheckResultsGenerator`
      // and the result is consumed by the legacy plugins all over the place, so we should keep it here for now. We assume
      // that when legacy callback is called license has been already propagated to the new platform security plugin and
      // features are up to date.
      server.plugins.xpack_main.info
        .feature(this.id)
        .registerLicenseCheckResultsGenerator(() => securityPlugin.license.getFeatures());
    },
  });
