/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

/**
 * Core's UIAM service
 *
 * @public
 */
export interface CoreUiamService {
  /**
   * Returns the Elasticsearch secondary client authentication header (`es-secondary-x-client-authentication`) with the
   * shared secret value. This header is used to authenticate requests from Kibana to Elasticsearch when using UIAM
   * credentials as secondary credentials.
   */
  getSecondaryClientAuthenticationHeader(): Record<string, string>;
}
