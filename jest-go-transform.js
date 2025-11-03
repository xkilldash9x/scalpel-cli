'use strict';

const babelJest = require('babel-jest').default;
const transformerInstance = babelJest.createTransformer();

module.exports = {
  async process(src, filename, config, options) {
    
    // Replace all Go template placeholders with valid JS values
    const cleanedSrc = src
      .replace('{{.SinksJSON}}', '[]')
      // --- FIX: Removed the extra quotes from these replacements ---
      .replace('{{.SinkCallbackName}}', '__MOCK_SINK_CALLBACK__')
      .replace('{{.ProofCallbackName}}', '__MOCK_PROOF_CALLBACK__')
      .replace('{{.ErrorCallbackName}}', '__MOCK_ERROR_CALLBACK__')
      // -----------------------------------------------------------
      .replace(/{{.IsTesting.*}}/g, 'true');

    // Pass the cleaned, valid JS to the real babel-jest transformer
    return await transformerInstance.process(cleanedSrc, filename, config, options);
  },
};