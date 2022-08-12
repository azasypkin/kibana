/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  EuiButton,
  EuiCodeBlock,
  EuiFlexGroup,
  EuiFlexItem,
  EuiIcon,
  EuiLoadingSpinner,
  EuiModal,
  EuiModalBody,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import type { FunctionComponent } from 'react';
import React, { useEffect, useState } from 'react';

import { useKibana } from '@kbn/kibana-react-plugin/public';

import type { UserProfileMfaData } from '../../../../common';
import { useSecurityApiClients } from '../../../components';
import { useUserProfile } from '../../../components/use_current_user';

export interface ChangeMfaModalProps {
  enroll: boolean;
  onCancel(): void;
  onSuccess?(): void;
}

export const ChangeMfaModal: FunctionComponent<ChangeMfaModalProps> = ({ enroll, onCancel }) => {
  const { services } = useKibana();
  const userProfile = useUserProfile<{ mfa: UserProfileMfaData }>('mfa');
  const [credential, setCredential] = useState<PublicKeyCredential | null | undefined>();
  const [credentialError, setCredentialError] = useState<any | undefined>();
  const { userProfiles } = useSecurityApiClients();
  const [loadingMessage, setLoadingMessage] = useState('Retrieving user information...');
  const [enrolled, setEnrolled] = useState(false);

  useEffect(() => {
    const userProfileValue = userProfile.value;
    const http = services.http;
    if (!userProfileValue || !http || enrolled) {
      return;
    }

    if (!enroll) {
      setLoadingMessage('Unenrolling security key...');
      userProfiles.update({ mfa: null }).then(
        () => {
          setTimeout(onCancel, 2000);
        },
        (err) => {
          setCredentialError(err);
          setCredential(null);
        }
      );
      return;
    }

    setLoadingMessage('Enrolling security key...');
    http
      .fetch<{ challenge: string }>('/internal/security/mfa/register_start')
      .then(({ challenge }) => {
        return navigator.credentials.create({
          publicKey: {
            challenge: Uint8Array.from(challenge, (c) => c.charCodeAt(0)),
            rp: { name: 'Elastic', id: 'localhost' },
            user: {
              id: Uint8Array.from(userProfileValue.uid, (c) => c.charCodeAt(0)),
              name: userProfileValue.user.username,
              displayName: userProfileValue.user.full_name ?? userProfileValue.user.username,
            },
            pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
            authenticatorSelection: {
              authenticatorAttachment: 'cross-platform',
              userVerification: 'discouraged',
              requireResidentKey: false,
            },
            timeout: 60000,
          },
        });
      })
      .then((newCredential) => {
        const pkCredential = newCredential as PublicKeyCredential;
        const pkResponse = pkCredential.response as AuthenticatorAttestationResponse;

        return http
          .fetch('/internal/security/mfa/register_finish', {
            method: 'POST',
            body: JSON.stringify({
              credentialId: pkCredential.id,
              clientDataJSON: window.btoa(
                String.fromCharCode(...new Uint8Array(pkResponse.clientDataJSON))
              ),
              attestationObject: window.btoa(
                String.fromCharCode(...new Uint8Array(pkResponse.attestationObject))
              ),
            }),
          })
          .then(() => pkCredential);
      })
      .then(
        (pkCredential) => {
          setEnrolled(true);
          setCredential(pkCredential);
          userProfiles.update({ test: null });
        },
        (err) => {
          setCredentialError(err);
          setCredential(null);
        }
      );
  }, [userProfile, services, userProfiles, onCancel, enrolled, enroll]);

  const verifyMfa = async () => {
    const http = services.http;
    if (!http) {
      return;
    }

    setLoadingMessage('Verifying security key...');
    setCredential(null);

    const { challenge, credentialId } = await http.fetch<{
      challenge: string;
      credentialId: string;
    }>('/internal/security/mfa/verify_start');

    navigator.credentials
      .get({
        publicKey: {
          rpId: 'localhost',
          challenge: Uint8Array.from(challenge, (c) => c.charCodeAt(0)),
          allowCredentials: [
            {
              id: Uint8Array.from(window.atob(credentialId), (c) => c.charCodeAt(0)),
              type: 'public-key',
            },
          ],
          userVerification: 'discouraged',
          timeout: 60000,
        },
      })
      .then((newCredential) => {
        const pkCredential = newCredential as PublicKeyCredential;
        const pkResponse = pkCredential.response as AuthenticatorAssertionResponse;

        return http
          .fetch('/internal/security/mfa/verify_finish', {
            method: 'POST',
            body: JSON.stringify({
              signature: window.btoa(String.fromCharCode(...new Uint8Array(pkResponse.signature))),
              clientDataJSON: window.btoa(
                String.fromCharCode(...new Uint8Array(pkResponse.clientDataJSON))
              ),
              authenticatorData: window.btoa(
                String.fromCharCode(...new Uint8Array(pkResponse.authenticatorData))
              ),
            }),
          })
          .then(() => pkCredential);
      })
      .then(
        (pkCredential) => {
          setCredential(pkCredential);
        },
        (err) => {
          setCredentialError(err);
          setCredential(null);
        }
      );
  };

  let content;
  const profileLoadError = userProfile.error ? userProfile.error : credentialError;
  if (profileLoadError) {
    content = (
      <EuiFlexGroup justifyContent="center" alignItems="center" direction="row" gutterSize="s">
        <EuiFlexItem grow={false}>
          <EuiIcon type="alert" />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiText>{profileLoadError.message}</EuiText>
        </EuiFlexItem>
      </EuiFlexGroup>
    );
  } else if (!credential) {
    content = (
      <EuiFlexGroup justifyContent="center" alignItems="center" direction="row" gutterSize="s">
        <EuiFlexItem grow={false}>
          <EuiLoadingSpinner size="l" />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiText>{loadingMessage}</EuiText>
        </EuiFlexItem>
      </EuiFlexGroup>
    );
  } else {
    const decoder = new TextDecoder('utf-8');
    content = (
      <EuiFlexGroup justifyContent="center" alignItems="center" direction="row" gutterSize="s">
        <EuiFlexItem style={{ maxWidth: '100%' }}>
          <EuiCodeBlock language="json" overflowHeight={300}>
            {JSON.stringify({
              id: credential.id,
              type: credential.type,
              challenge: window.atob(
                JSON.parse(decoder.decode(credential.response.clientDataJSON)).challenge
              ),
              signature: (credential.response as AuthenticatorAssertionResponse).signature
                ? String.fromCharCode(
                    ...new Uint8Array(
                      (credential.response as AuthenticatorAssertionResponse).signature
                    )
                  )
                : undefined,
            })}
          </EuiCodeBlock>
          <EuiButton onClick={verifyMfa}>Verify</EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
    );
  }

  return (
    <EuiModal onClose={onCancel}>
      <EuiSpacer />
      <EuiModalBody>{content}</EuiModalBody>
    </EuiModal>
  );
};
