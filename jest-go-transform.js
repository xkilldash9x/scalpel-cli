'use strict';

// We need to chain our simple string replacement with the real babel-jest transformer
const babelJest = require('babel-jest').default;

module.exports = {
  // This process function will be called by Jest
  process(src, filename, config, options) {
    
    // 1. Replace all Go template placeholders with valid JS defaults
    const cleanedSrc = src
      .replace('{{.SinksJSON}}', '[]')
      .replace('{{.SinkCallbackName}}', '"__MOCK_SINK_CALLBACK__"')
      .replace('{{.ProofCallbackName}}', '"__MOCK_PROOF_CALLBACK__"')
      .replace('{{.ErrorCallbackName}}', '"__MOCK_ERROR_CALLBACK__"')
      // This regex handles {{.IsTesting | default false}} or similar
      .replace(/{{.IsTesting.*}}/g, 'true');

    // 2. Pass the cleaned, valid JS to the real babel-jest transformer
    return babelJest.process(cleanedSrc, filename, config, options);
  },
};
