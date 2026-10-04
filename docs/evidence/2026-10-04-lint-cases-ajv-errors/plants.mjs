// The five schema violations both trials plant in a parsed copy of
// fixtures/cases.json. Each mutates the document in place.
const find = (doc, pick) => doc.cases.find(pick);

export const plants = {
  'missing-required': (doc) => { delete doc.cases[0].description; },
  'wrong-type': (doc) => { find(doc, (c) => c.maxMillis !== undefined).maxMillis = '100'; },
  'unknown-property': (doc) => { doc.cases[0].bogus = 1; },
  'ok-case-without-environment': (doc) => {
    delete find(doc, (c) => c.operation === 'verifyReceipt' && c.expected.status === 'ok')
      .expected.environment;
  },
  'oneOf-matching-nothing': (doc) => {
    find(doc, (c) => c.config?.trustedRoots?.source === 'defaults').config.trustedRoots.source = 'bundled';
  },
};

// The Ajv options lint-cases uses, minus allErrors and verbose.
export const strict = { strict: true, strictTypes: false, strictRequired: false };
