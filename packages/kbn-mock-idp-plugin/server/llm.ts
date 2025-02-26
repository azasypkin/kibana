/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { adjectives, animals, uniqueNamesGenerator } from 'unique-names-generator';
import { inspect } from 'util';

import type { KibanaFeature } from '@kbn/features-plugin/common';
import type { Logger } from '@kbn/logging';

const OLLAMA_HOST = process.env.OLAMA_HOST || 'http://localhost:11434';
const GEMINI_HOST = process.env.GEMINI_HOST || 'https://generativelanguage.googleapis.com';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';

const SUPPORTED_MODELS = new Map<'ollama' | 'gemini', Set<string>>([
  [
    'ollama',
    new Set([
      'mistral-small:latest',
      'mistral-nemo:latest',
      'qwen2.5:1.5b',
      'qwen2.5:7b',
      'qwen2.5:14b',
    ]),
  ],
  ['gemini', new Set(['gemini-1.5-flash', 'gemini-2.0-flash'])],
]);

interface LlmResponse {
  kibana: Array<{ id: string; access: string }>;
  elasticsearch: Array<{ index: string; access: string }>;
  accessToSystemIndices: string;
}

export async function generateRole(
  logger: Logger,
  features: KibanaFeature[],
  model: string,
  userPrompt: string
) {
  const [modelProvider, modelId] = model.toLowerCase().split('/') as ['ollama' | 'gemini', string];
  const models = SUPPORTED_MODELS.get(modelProvider);
  if (!models) {
    logger.error(`Model provider "${modelProvider}" is not supported.`);
    throw new Error(`Model provider "${modelProvider}" is not supported.`);
  }
  if (!models.has(modelId)) {
    logger.error(`Model "${modelId}" (${modelProvider}) is not supported.`);
    throw new Error(`Model "${modelId}" (${modelProvider}) is not supported.`);
  }

  if (modelProvider === 'gemini' && !GEMINI_API_KEY) {
    logger.error('GEMINI_API_KEY is required for Gemini model provider.');
    throw new Error('GEMINI_API_KEY is required for Gemini model provider.');
  }

  // 3. Generate a system prompt.
  const systemPrompt = `
You are an expert in creating roles for the Elasticsearch & Kibana.
You are given a description of the permissions that the role should grant and based on that description, you will need
to come up with the JSON description of the role STRICTLY according to the following schema (especially "enums"), and
NO other text MUST be included (no thinking, no reasoning, no explanations, no comments), just plain JSON.

## Role Schema
\`\`\`json
{
  "type": "object",
  "properties": {
    "kibana": {
      "type": "array",
      "minItems": 0,
      "items": {
        "type": "object",
        "properties": {
          "id": { "enum": ${JSON.stringify(features.map((f) => f.id).concat(['base']))} },
          "access": { "enum": ["all", "read"] }
        },
        "required": ["id", "access"]
      }
    },
    "elasticsearch": {
      "type": "array",
      "minItems": 0,
      "items": {
        "type": "object",
        "properties": { "index": { "type": "string" }, "access": { "enum": ["all", "read"] } },
        "required": ["index", "access"]
      }
    },
    "accessToSystemIndices": { "enum": ["all", "read", "none"] }
  },
  "required": ["kibana", "elasticsearch", "accessToSystemIndices"]
}
\`\`\`

## The "kibana" role portion

The "kibana" role portion MUST ONLY contain a list of features related to Kibana, where "id" is feature ID, and "access"
is the privilege that will be granted to specified feature. Here's the list of available features with IDs, names and
descriptions that you should use to figure out which features are assumed in the query. You MUST pick feature IDs
ONLY from this list.
\`\`\`json
[
${features
  .map(({ id, name, app }) => {
    const apps = app.filter((a) => a !== 'kibana');
    return JSON.stringify({
      id,
      name,
      description: apps.length > 0 ? `Grants access to the following apps: ${apps.join(', ')}` : '',
    });
  })
  .join(',\n')}
]
\`\`\`

When user mentions they want to have access to all *features* (meaning all applications in Kibana), use "base" as the
feature ID (that's a special keyword). Don't make new feature IDs, if you cannot match feature the user is asking for -
ask for clarification.

The "access" property defines a level of access, it can either be "all" (manage, write, all - all are aliases for "all",
that's the highest level of access to a certain feature) or "read" (read, view - all are aliases for "read").

## The "elasticsearch" role portion

The "elasticsearch" portion ONLY contains a list of data indices that user should have access to, it can contain index
name or index pattern. The "access" is the privilege that will be granted to specified data index or index pattern.
When user mentions they want to have access to all indices, use "*" as the "index" (that's a special keyword). You should
use "read" access unless user explicitly mentions they want to have elevated access (full, all or write).

## The "accessToSystemIndices" role portion

The "accessToSystemIndices" property should be set to "none" by default unless user explicitly mentions that
 they want to access ALL system or hidden indices without explicitly specifying their name. It can either be "all"
 (manage, write, all - all are aliases for "all", that's the highest level of access to a certain feature) or "read" (
 read, view - all are aliases for "read").
`;

  logger.info(`<|SYSTEM PROMPT|> ${systemPrompt}`);
  logger.info(`---`);
  logger.info(`<|USER PROMPT|> ${userPrompt}`);
  logger.info(`---`);

  // 4. Query the model.
  const llmResponse = await queryModel(logger, modelProvider, modelId, systemPrompt, userPrompt);
  logger.info(`<|LLM RESPONSE (${model})|> ${inspect(llmResponse, { depth: 100 })}`);
  logger.info(`---`);

  // 5. Generate the role name.
  const roleName = uniqueNamesGenerator({ dictionaries: [adjectives, animals], length: 2 });

  // 6. Construct the role.
  const role = constructRole(logger, userPrompt, roleName, features, llmResponse);
  logger.info(`<|ROLE|> ${inspect(role, { depth: 100 })}`);
  logger.info(`---`);

  // 7. Create the role in Kibana.
  return role;
}

async function queryModel(
  logger: Logger,
  modelProvider: 'ollama' | 'gemini',
  modelId: string,
  systemPrompt: string,
  userPrompt: string
) {
  let promptResult;
  if (modelProvider === 'ollama') {
    promptResult = (
      await (
        await fetch(`${OLLAMA_HOST}/api/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: modelId,
            system: systemPrompt,
            prompt: userPrompt,
            format: 'json',
            stream: false,
            options: { num_ctx: 32000 },
          }),
        })
      ).json()
    ).response;
  } else {
    promptResult =
      (
        await (
          await fetch(
            `${GEMINI_HOST}/v1beta/models/${modelId}:generateContent?key=${GEMINI_API_KEY}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                system_instruction: { parts: { text: systemPrompt } },
                contents: { parts: { text: userPrompt } },
                generationConfig: { response_mime_type: 'application/json' },
              }),
            }
          )
        ).json()
      ).candidates?.[0].content.parts?.[0].text || '';
  }

  try {
    return JSON.parse(promptResult) as LlmResponse;
  } catch (err) {
    logger.error(
      `Failed to parse LLM response (${modelProvider}/${modelId}): ${inspect(promptResult, {
        depth: 100,
      })}`
    );
    throw err;
  }
}

function constructRole(
  logger: Logger,
  userPrompt: string,
  roleName: string,
  features: KibanaFeature[],
  llmResponse: LlmResponse
) {
  const indices = llmResponse.elasticsearch.map((es) => ({
    names: [es.index],
    privileges: [es.access],
    field_security: { grant: ['*'], except: [] },
    allow_restricted_indices: es.index.startsWith('.'),
  }));
  if (llmResponse.accessToSystemIndices !== 'none') {
    indices.push({
      names: ['*'],
      privileges: [llmResponse.accessToSystemIndices],
      field_security: { grant: ['*'], except: [] },
      allow_restricted_indices: true,
    });
  }

  let kibana = null;
  if (llmResponse.kibana.length > 0) {
    const basePrivilege = llmResponse.kibana.find((k) => k.id === 'base');

    const featurePrivileges = [];
    if (!basePrivilege) {
      for (const k of llmResponse.kibana) {
        const validFeature = features.find((f) => f.id === k.id);
        if (!validFeature) {
          logger.error(`Failed to construct role: feature with ID "${k.id}" is not supported.`);
          throw new Error(`Feature with ID "${k.id}" is not supported.`);
        }
        featurePrivileges.push([k.id, [k.access]]);
      }
    }

    kibana = {
      spaces: ['*'],
      base: basePrivilege ? [basePrivilege.access] : [],
      feature: featurePrivileges.length > 0 ? Object.fromEntries(featurePrivileges) : {},
    };
  }

  return {
    name: roleName,
    description: `${roleName}: ${userPrompt}`,
    kibana: kibana ? [kibana] : [],
    elasticsearch: {
      cluster: [],
      indices,
      run_as: [],
    },
  };
}
