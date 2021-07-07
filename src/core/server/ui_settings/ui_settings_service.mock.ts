/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

import type { PublicMethodsOf } from '@kbn/utility-types';
import {
  IUiSettingsClient,
  InternalUiSettingsServiceSetup,
  InternalUiSettingsServiceStart,
  InternalUiSettingsServicePreboot,
} from './types';
import type { UiSettingsService } from './ui_settings_service';

const createClientMock = () => {
  const mocked: jest.Mocked<IUiSettingsClient> = {
    getRegistered: jest.fn(),
    get: jest.fn(),
    getAll: jest.fn(),
    getUserProvided: jest.fn(),
    setMany: jest.fn(),
    set: jest.fn(),
    remove: jest.fn(),
    removeMany: jest.fn(),
    isOverridden: jest.fn(),
    isSensitive: jest.fn(),
  };
  mocked.get.mockResolvedValue(false);
  mocked.getAll.mockResolvedValue({});
  mocked.getRegistered.mockReturnValue({});
  mocked.getUserProvided.mockResolvedValue({});
  return mocked;
};

const createPrebootMock = () => {
  const mocked: jest.Mocked<InternalUiSettingsServicePreboot> = {
    defaultsClient: jest.fn(),
  };

  mocked.defaultsClient.mockReturnValue(createClientMock());

  return mocked;
};

const createSetupMock = () => {
  const mocked: jest.Mocked<InternalUiSettingsServiceSetup> = {
    register: jest.fn(),
  };

  return mocked;
};

const createStartMock = () => {
  const mocked: jest.Mocked<InternalUiSettingsServiceStart> = {
    asScopedToClient: jest.fn(),
  };

  mocked.asScopedToClient.mockReturnValue(createClientMock());

  return mocked;
};

type UiSettingsServiceContract = PublicMethodsOf<UiSettingsService>;
const createMock = () => {
  const mocked: jest.Mocked<UiSettingsServiceContract> = {
    preboot: jest.fn(),
    setup: jest.fn(),
    start: jest.fn(),
    stop: jest.fn(),
  };
  mocked.preboot.mockResolvedValue(createPrebootMock());
  mocked.setup.mockResolvedValue(createSetupMock());
  mocked.start.mockResolvedValue(createStartMock());
  return mocked;
};

export const uiSettingsServiceMock = {
  createPrebootContract: createPrebootMock,
  createSetupContract: createSetupMock,
  createStartContract: createStartMock,
  createClient: createClientMock,
  create: createMock,
};
