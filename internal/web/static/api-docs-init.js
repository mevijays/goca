// Boots Swagger UI against goca's own embedded OpenAPI spec. Kept as its own
// file (not an inline <script> block) because the portal's Content-Security-
// Policy is script-src 'self' with no 'unsafe-inline' - the same reason
// app.js is external rather than inlined into layout.html.
(function () {
  "use strict";
  window.ui = SwaggerUIBundle({
    url: "/settings/api-docs/openapi.yaml",
    dom_id: "#swagger-ui",
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    plugins: [SwaggerUIBundle.plugins.DownloadUrl],
    layout: "StandaloneLayout",
    docExpansion: "list",
    defaultModelsExpandDepth: -1,
    // Same-origin only, matching every other request this portal makes.
    validatorUrl: null,
    persistAuthorization: true,
  });
})();
