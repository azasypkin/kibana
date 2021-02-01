/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { i18n } from '@kbn/i18n';
import { CoreSetup, HttpSetup, StartServicesAccessor } from 'src/core/public';

interface CreateDeps {
  application: CoreSetup['application'];
  getStartServices: StartServicesAccessor;
  http: HttpSetup;
}

export const logoutApp = Object.freeze({
  id: 'security_logout',
  create({ application, http, getStartServices }: CreateDeps) {
    http.anonymousPaths.register('/logout');
    application.register({
      id: this.id,
      title: i18n.translate('xpack.security.logoutAppTitle', { defaultMessage: 'Logout' }),
      chromeless: true,
      appRoute: '/logout',
      async mount() {
        window.sessionStorage.clear();

        const [[coreStart], { location }] = await Promise.all([
          getStartServices(),
          http.post<{ location: string }>(`/api/security/logout${window.location.search}`),
        ]);

        await coreStart.application.navigateToUrl(location);

        return () => {};
      },
    });
  },
});
