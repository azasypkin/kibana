/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { randomBytes } from 'crypto';
import * as fido from 'fido2-lib';
import { format, promisify } from 'util';

import { schema } from '@kbn/config-schema';

import type { RouteDefinitionParams } from '..';
import type { UserProfileMfaData } from '../../../common';
import { getDetailedErrorMessage } from '../../errors';
import { createLicensedRouteHandler } from '../licensed_route_handler';

function getFidoValidator() {
  return new fido.Fido2Lib({
    rpId: 'localhost',
    authenticatorAttachment: 'cross-platform',
    authenticatorUserVerification: 'discouraged',
    cryptoParams: [-7],
  });
}

async function verifyAttestation(
  credentialId: string,
  challenge: string,
  clientDataJSON: string,
  attestationObject: string
) {
  const idBuffer = Buffer.from(credentialId, 'base64');
  return await getFidoValidator().attestationResult(
    {
      rawId: idBuffer.buffer.slice(idBuffer.byteOffset, idBuffer.byteOffset + idBuffer.byteLength),
      response: { attestationObject, clientDataJSON },
    },
    {
      challenge: Buffer.from(btoa(challenge), 'base64').toString('base64url'),
      origin: 'http://localhost:5601',
      factor: 'either',
    }
  );
}

async function verifyAssertion(
  credentialId: string,
  signature: string,
  challenge: string,
  publicKey: string,
  clientDataJSON: string,
  authenticatorData: string
) {
  const idBuffer = Buffer.from(credentialId, 'base64');
  const authenticatorDataBuffer = Buffer.from(authenticatorData, 'base64');
  return await getFidoValidator().assertionResult(
    {
      rawId: idBuffer.buffer.slice(idBuffer.byteOffset, idBuffer.byteOffset + idBuffer.byteLength),
      response: {
        authenticatorData: authenticatorDataBuffer.buffer.slice(
          authenticatorDataBuffer.byteOffset,
          authenticatorDataBuffer.byteOffset + authenticatorDataBuffer.byteLength
        ),
        clientDataJSON,
        signature,
      },
    },
    {
      challenge: Buffer.from(btoa(challenge), 'base64').toString('base64url'),
      origin: 'http://localhost:5601',
      factor: 'either',
      publicKey,
      userHandle: null,
      prevCounter: 0,
    }
  );
}

export function defineMfaRoutes({ router, getUserProfileService, logger }: RouteDefinitionParams) {
  router.get(
    { path: '/internal/security/mfa/register_start', validate: false },
    async (context, request, response) => {
      const userProfileService = getUserProfileService();

      // 1. Retrieve user profile.
      const profile = await userProfileService.getCurrent({ request, dataPath: 'mfa' });
      if (!profile) {
        return response.forbidden();
      }

      // 2. Generate challenge.
      const challenge = (await promisify(randomBytes)(64)).toString('base64');

      // 3. Store challenge in the profile.
      await userProfileService.update(profile.uid, { mfa: { challenge } });

      return response.ok({ body: { challenge } });
    }
  );

  router.post(
    {
      path: '/internal/security/mfa/register_finish',
      validate: {
        body: schema.object({
          credentialId: schema.string(),
          clientDataJSON: schema.string(),
          attestationObject: schema.string(),
        }),
      },
    },
    createLicensedRouteHandler(async (context, request, response) => {
      const userProfileService = getUserProfileService();

      // 1. Retrieve user profile with the challenge.
      const profile = await userProfileService.getCurrent<{ mfa: UserProfileMfaData }, {}>({
        request,
        dataPath: 'mfa',
      });

      // 2. Validate challenge.
      if (!profile?.data.mfa?.challenge) {
        return response.forbidden();
      }

      try {
        // 3. Decode attestation.
        const attestation = await verifyAttestation(
          request.body.credentialId,
          profile?.data.mfa?.challenge,
          request.body.clientDataJSON,
          request.body.attestationObject
        );
        logger.info(`Attestation result: ${format(attestation)}`);

        // 4. Store attestation.
        await userProfileService.update<{ mfa: UserProfileMfaData }>(profile.uid, {
          mfa: {
            attestation: {
              credentialId: request.body.credentialId,
              publicKey: attestation.authnrData.get('credentialPublicKeyPem'),
            },
            challenge: null!,
          },
        });
      } catch (err) {
        logger.error(`MFA verification failed: ${getDetailedErrorMessage(err)}`);
        return response.forbidden({ body: getDetailedErrorMessage(err) });
      }

      return response.ok();
    })
  );

  router.get(
    {
      path: '/internal/security/mfa/verify_start',
      validate: false,
    },
    createLicensedRouteHandler(async (context, request, response) => {
      const userProfileService = getUserProfileService();

      // 1. Retrieve user profile with the user handle.
      const profile = await userProfileService.getCurrent<{ mfa: UserProfileMfaData }, {}>({
        request,
        dataPath: 'mfa',
      });

      // 2. Check if MFA is configured.
      if (!profile?.data.mfa?.attestation) {
        return response.forbidden();
      }

      // 3. Generate verification challenge.
      const challenge = (await promisify(randomBytes)(64)).toString('base64');

      // 4. Store challenge in the profile.
      await userProfileService.update(profile.uid, { mfa: { challenge } });

      return response.ok({
        body: {
          challenge,
          credentialId: Buffer.from(
            profile.data.mfa.attestation.credentialId,
            'base64url'
          ).toString('base64'),
        },
      });
    })
  );

  router.post(
    {
      path: '/internal/security/mfa/verify_finish',
      validate: {
        body: schema.object({
          signature: schema.string(),
          clientDataJSON: schema.string(),
          authenticatorData: schema.string(),
        }),
      },
    },
    createLicensedRouteHandler(async (context, request, response) => {
      const userProfileService = getUserProfileService();

      // 1. Retrieve user profile with the challenge.
      const profile = await userProfileService.getCurrent<{ mfa: UserProfileMfaData }, {}>({
        request,
        dataPath: 'mfa',
      });

      // 2. Check MFA is configured and challenge is generated.
      if (!profile?.data.mfa?.challenge || !profile?.data.mfa?.attestation) {
        return response.forbidden();
      }

      try {
        // 3. Decode and verify assertion.
        const assertion = await verifyAssertion(
          profile.data.mfa.attestation.credentialId,
          Buffer.from(request.body.signature, 'base64').toString('base64url'),
          profile.data.mfa.challenge,
          profile.data.mfa.attestation.publicKey,
          request.body.clientDataJSON,
          request.body.authenticatorData
        );

        logger.info(`Assertion result: ${format(assertion)}`);
      } catch (err) {
        logger.error(`MFA verification failed: ${getDetailedErrorMessage(err)}`);
        return response.forbidden({ body: getDetailedErrorMessage(err) });
      }

      return response.ok();
    })
  );

  router.post(
    {
      path: '/internal/security/mfa/login_verify_start',
      validate: {
        body: schema.object({
          params: schema.object({
            username: schema.string({ minLength: 1 }),
            password: schema.string({ minLength: 1 }),
          }),
        }),
      },
      options: { authRequired: false },
    },
    createLicensedRouteHandler(async (context, request, response) => {
      const userProfileService = getUserProfileService();

      // 1. Activate profile
      const activatedProfile = await userProfileService.activate({
        type: 'password',
        username: request.body.params.username,
        password: request.body.params.password,
      });

      // 2. Retrieve user profile data.
      const profiles = await userProfileService.bulkGet<{ mfa: UserProfileMfaData }>({
        uids: new Set([activatedProfile.uid]),
        dataPath: 'mfa',
      });

      // 2. Check if MFA is configured.
      if (!profiles[0]?.data.mfa?.attestation) {
        return response.ok({ body: { mfaRequired: false } });
      }

      // 3. Generate verification challenge.
      const challenge = (await promisify(randomBytes)(64)).toString('base64');

      // 4. Store challenge in the profile.
      await userProfileService.update(activatedProfile.uid, { mfa: { challenge } });

      return response.ok({
        body: {
          mfaRequired: true,
          challenge,
          credentialId: Buffer.from(
            profiles[0].data.mfa.attestation.credentialId,
            'base64url'
          ).toString('base64'),
        },
      });
    })
  );

  router.post(
    {
      path: '/internal/security/mfa/login_verify_finish',
      validate: {
        body: schema.object({
          signature: schema.string(),
          clientDataJSON: schema.string(),
          authenticatorData: schema.string(),
          params: schema.object({
            username: schema.string({ minLength: 1 }),
            password: schema.string({ minLength: 1 }),
          }),
        }),
      },
      options: { authRequired: false },
    },
    createLicensedRouteHandler(async (context, request, response) => {
      const userProfileService = getUserProfileService();

      // 1. Activate profile
      const activatedProfile = await userProfileService.activate({
        type: 'password',
        username: request.body.params.username,
        password: request.body.params.password,
      });

      // 2. Retrieve user profile data.
      const profiles = await userProfileService.bulkGet<{ mfa: UserProfileMfaData }>({
        uids: new Set([activatedProfile.uid]),
        dataPath: 'mfa',
      });

      // 3. Check MFA is configured and challenge is generated.
      if (!profiles[0]?.data.mfa?.challenge || !profiles[0]?.data.mfa?.attestation) {
        return response.forbidden();
      }

      try {
        // 4. Decode and verify assertion.
        const assertion = await verifyAssertion(
          profiles[0].data.mfa.attestation.credentialId,
          Buffer.from(request.body.signature, 'base64').toString('base64url'),
          profiles[0].data.mfa.challenge,
          profiles[0].data.mfa.attestation.publicKey,
          request.body.clientDataJSON,
          request.body.authenticatorData
        );

        logger.info(`Assertion result: ${format(assertion)}`);
      } catch (err) {
        logger.error(`MFA verification failed: ${getDetailedErrorMessage(err)}`);
        return response.forbidden({ body: getDetailedErrorMessage(err) });
      }

      return response.ok();
    })
  );
}
