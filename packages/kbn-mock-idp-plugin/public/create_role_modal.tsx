/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import {
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCodeBlock,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSelect,
  EuiSkeletonText,
  EuiSpacer,
} from '@elastic/eui';
import React, { useState } from 'react';

import type { CoreStart } from '@kbn/core-lifecycle-browser';
import { useKibana } from '@kbn/kibana-react-plugin/public';

export interface CreateRoleModalProps {
  onClose: (roleName?: string) => void;
}

export const CreateRoleModal = ({ onClose }: CreateRoleModalProps) => {
  const { services } = useKibana<CoreStart>();

  const [roleDefinition, setRoleDefinition] = useState<
    { valid: true; role: Record<string, unknown> } | { valid: false; message?: string }
  >({ valid: false });

  const [prompt, setPrompt] = useState<string>('');
  const [model, setModel] = useState<string>('ollama/qwen2.5:14b');
  const [isLoading, setIsLoading] = useState(false);

  const generateRole = async () => {
    setIsLoading(true);
    try {
      const response = await services.http.post<Record<string, unknown>>(
        '/mock_idp/llm_role/generate',
        { body: JSON.stringify({ prompt, model }) }
      );
      setRoleDefinition({ valid: true, role: response });
    } catch {
      setRoleDefinition({ valid: false, message: 'Failed to generate role' });
    }
    setIsLoading(false);
  };

  const saveRole = async () => {
    if (!roleDefinition.valid) {
      return;
    }

    const { name, description, kibana, elasticsearch } = roleDefinition.role;
    setIsLoading(true);
    try {
      await services.http.put(`/api/security/role/${name}`, {
        body: JSON.stringify({ description, kibana, elasticsearch }),
        // OMG! OMG! OMG! Hardcoded superuser credentials!!!
        headers: { Authorization: `Basic ${btoa('elastic_serverless:changeme')}` },
      });
      onClose(roleDefinition.role.name as string);
    } catch {
      //
    }
    setIsLoading(false);
  };

  return (
    <EuiModal aria-labelledby="create-role-dialog" onClose={() => onClose()}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>Create new role</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiForm>
          <EuiSelect
            disabled={isLoading}
            options={[
              {
                value: 'ollama/qwen2.5:1.5b',
                text: 'Qwen2.5-1.5B (local via Ollama)',
              },
              {
                value: 'ollama/qwen2.5:7b',
                text: 'Qwen2.5-7B (local via Ollama)',
              },
              {
                value: 'ollama/qwen2.5:14b',
                text: 'Qwen2.5-14B (local via Ollama)',
              },
              {
                value: 'ollama/mistral-nemo:latest',
                text: 'Mistral NeMo-12B (local via Ollama)',
              },
              {
                value: 'gemini/gemini-2.0-flash',
                text: 'Gemini 2.0 Flash',
              },
            ]}
            value={model}
            onChange={(e) => setModel(e.target.value)}
          />
          <EuiSpacer />
          <EuiFieldText
            name={'role-prompt'}
            id={'role-prompt'}
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            className={'rolePrompt'}
            placeholder="Describe the role, e.g., view logs-* in Discover"
            disabled={isLoading}
            append={
              <EuiButtonIcon
                aria-label={'Generate role'}
                iconType={'sparkles'}
                isLoading={isLoading}
                isDisabled={isLoading}
                onClick={() => generateRole()}
              />
            }
          />
          <EuiSpacer />
          <EuiCodeBlock language="json" fontSize="m" paddingSize="m" css={{ width: '400px' }}>
            <EuiSkeletonText
              lines={6}
              size="m"
              isLoading={isLoading}
              contentAriaLabel="Example text"
            >
              {roleDefinition.valid
                ? JSON.stringify(roleDefinition.role, null, 2)
                : roleDefinition.message ||
                  `{
  "kibana": [],
  "elasticsearch": {
    "cluster": [],
    "indices": [],
    "run_as": []
  }
}`}
            </EuiSkeletonText>
          </EuiCodeBlock>
        </EuiForm>
      </EuiModalBody>
      <EuiModalFooter>
        <EuiFlexGroup>
          <EuiFlexItem>
            <EuiButtonEmpty onClick={() => onClose()}>Cancel</EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiButton isDisabled={isLoading || !roleDefinition.valid} onClick={() => saveRole()}>
              Save
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiModalFooter>
    </EuiModal>
  );
};
