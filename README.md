# P12 Certificate Manager

## Table of Contents
- [Project Description](#project-description)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Running Tests](#running-tests)

## Project Description
This project is a tool to manage Certificate Authorities (CAs) and generate P12 certificates. It provides an API to create PGP key pairs and P12 certificates for user validation.

## Features
-   Create and manage Certificate Authorities (CAs).
-   Generate P12 certificates for user validation.
-   API for creating PGP key pairs.

## Tech Stack
-   Node.js
-   Express
-   Pug
-   Jest

## Prerequisites
-   Node.js
-   npm

## Installation
1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/p12-certificate-manager.git
    ```
2.  Install the dependencies:
    ```bash
    npm install
    ```

## Configuration
1.  Create a `.env` file in the root of the project.
2.  Add the following environment variables to the `.env` file:
    ```
    ADMIN_USER=your_admin_user
    ADMIN_PASSWORD=your_admin_password
    SESSION_SECRET=your_session_secret
    ```

## Usage
1.  Start the application:
    ```bash
    node index.js
    ```
2.  Open your browser and navigate to `http://localhost:3000`.

## Running Tests
1.  Run the tests:
    ```bash
    npm test
    ```
