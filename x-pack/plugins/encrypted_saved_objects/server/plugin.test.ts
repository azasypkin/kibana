/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { Observable } from 'rxjs';
import { ServiceStatusLevels } from '../../../../src/core/server';
import { Plugin } from './plugin';
import { ConfigSchema } from './config';

import { coreMock } from 'src/core/server/mocks';
import { securityMock } from '../../security/server/mocks';

describe('EncryptedSavedObjects Plugin', () => {
  describe('setup()', () => {
    it('exposes proper contract', () => {
      const plugin = new Plugin(
        coreMock.createPluginInitializerContext(
          ConfigSchema.validate({ encryptionKey: 'z'.repeat(32) }, { dist: true })
        )
      );

      const mockCore = coreMock.createSetup();
      expect(plugin.setup(mockCore, { security: securityMock.createSetup() }))
        .toMatchInlineSnapshot(`
        Object {
          "createMigration": [Function],
          "registerType": [Function],
        }
      `);
      expect(mockCore.status.set).not.toHaveBeenCalled();
    });

    it('properly reports status if encryption key is not specified', () => {
      const plugin = new Plugin(
        coreMock.createPluginInitializerContext(ConfigSchema.validate({}, { dist: true }))
      );

      const mockCore = coreMock.createSetup();
      expect(plugin.setup(mockCore, { security: securityMock.createSetup() }))
        .toMatchInlineSnapshot(`
        Object {
          "createMigration": [Function],
          "registerType": [Function],
        }
      `);
      expect(mockCore.status.set).toHaveBeenCalledTimes(1);
      expect(mockCore.status.set).toHaveBeenCalledWith(expect.any(Observable));
      const [[statusObservable]] = mockCore.status.set.mock.calls;

      const mockHandler = jest.fn();
      statusObservable.subscribe(mockHandler);

      expect(mockHandler).toHaveBeenCalledTimes(1);
      expect(mockHandler).toHaveBeenCalledWith({
        level: ServiceStatusLevels.degraded,
        summary: 'Saved objects encryption key is not set.',
        detail:
          'Saved objects encryption key is not set. This will severely limit Kibana functionality. ' +
          'Please set xpack.encryptedSavedObjects.encryptionKey in the kibana.yml or use the bin/kibana-encryption-keys command.',
        documentationUrl: `https://www.elastic.co/guide/en/kibana/branch/xpack-security-secure-saved-objects.html#xpack-security-secure-saved-objects`,
        meta: { encryptionKeyIsMissing: true },
      });
    });
  });

  describe('start()', () => {
    it('exposes proper contract', async () => {
      const plugin = new Plugin(
        coreMock.createPluginInitializerContext(
          ConfigSchema.validate({ encryptionKey: 'z'.repeat(32) }, { dist: true })
        )
      );
      await plugin.setup(coreMock.createSetup(), { security: securityMock.createSetup() });

      const startContract = plugin.start();
      await expect(startContract).toMatchInlineSnapshot(`
              Object {
                "getClient": [Function],
                "isEncryptionError": [Function],
              }
            `);

      expect(startContract.getClient()).toMatchInlineSnapshot(`
              Object {
                "getDecryptedAsInternalUser": [Function],
              }
            `);
    });
  });
});
