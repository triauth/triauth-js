import globals from "globals";
import pluginJs from "@eslint/js";


/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    files: ["**/*.js"],
    languageOptions: {
      sourceType: "module",
      globals: {
        ...globals.browser, // Include browser globals
        ...globals.node,    // Include Node.js globals
      },
    }
  },
  {languageOptions: { globals: {...globals.browser, ...globals.node} }},
  pluginJs.configs.recommended,
  {
    // src/ owns its URL handling: the canonical-URL grammar in Helpers gives identical verdicts
    // on every runtime, and njs ships no URL at all — keep the globals out of the library.
    files: ["src/**/*.js"],
    rules: {
      "no-restricted-globals": [
        "error",
        { name: "URL", message: "Use the Helpers canonical-URL statics (isCanonicalUrl / getBaseUrl / urlHost)." },
        { name: "URLSearchParams", message: "Redirect parameters are base64url and appended verbatim (see AuthenticationEndpoint#urlFor)." },
        { name: "TextEncoder", message: "Use Helpers.stringToUtf8Bytes — strict (rejects unpaired surrogates) and byte-identical on every engine." },
        { name: "TextDecoder", message: "Use Helpers.utf8BytesToString — strict (rejects ill-formed UTF-8, keeps a BOM byte-visible)." },
        { name: "Buffer", message: "src/ is engine-neutral; convert bytes with Helpers.stringToUtf8Bytes / Helpers.utf8BytesToString." },
      ],
    },
  },
];
