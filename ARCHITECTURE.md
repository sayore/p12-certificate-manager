# Architecture

This document provides a high-level overview of the P12 Certificate Manager's architecture.

## Components

The application is composed of the following main components:

-   **`index.js`**: The main entry point of the application. It sets up the Express server, middleware, and routes.
-   **`services/`**: This directory contains the core business logic of the application.
    -   **`caService.js`**: Manages the creation and listing of Certificate Authorities (CAs).
    -   **`pgpService.js`**: Handles the generation and management of PGP keys.
    -   **`x509Service.js`**: Manages the issuance and revocation of X.509 certificates.
    -   **`job-manager.js`**: A simple in-memory job queue for running long-running tasks in the background.
    -   **`utils.js`**: A collection of utility functions used throughout the application.
-   **`views/`**: This directory contains the Pug templates for the application's user interface.
-   **`public/`**: This directory contains static assets such as CSS and JavaScript files.
-   **`tests/`**: This directory contains the Jest tests for the application.

## High-Level Flow

1.  The user interacts with the application through the web interface.
2.  The routes in `index.js` handle the user's requests and call the appropriate service functions.
3.  The service functions in the `services/` directory perform the core logic of the application, such as creating CAs, generating PGP keys, and issuing certificates.
4.  The service functions use the `runCommand` function in `services/utils.js` to execute shell commands for OpenSSL and GPG.
5.  Long-running tasks, such as PGP key generation, are run as background jobs using the `job-manager.js`.
6.  The Pug templates in the `views/` directory are rendered and sent to the user's browser.
