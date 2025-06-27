# Refactoring for Multi-User GitHub Token Support

This update refactors the server to support passing a `GITHUB_PERSONAL_ACCESS_TOKEN` with each individual tool call. This is achieved using Node.js's `AsyncLocalStorage` API, which provides a robust and maintainable way to handle concurrent, request-specific contexts.

This approach enables multiple users to interact with the server using their own GitHub credentials, without the risk of token leakage between concurrent requests.

## Key Changes

- **`AsyncLocalStorage` for Context Management**: A new `common/context.ts` file was created to export a shared `authStorage` instance. This instance is used to store the authentication token for the duration of a single tool call.

- **Request-Scoped Context**: The main request handler in `index.ts` now wraps the tool execution logic in `authStorage.run()`. This creates a unique context for each incoming request, safely isolating each user's token.

- **Centralized Token Access**: The core `githubRequest` function in `common/utils.ts` was updated to retrieve the token directly from `authStorage`. This eliminates the need to pass the token as a parameter through every intermediate function.

- **Simplified Operations**: The function signatures and schemas in the `operations/` directory are no longer modified for token handling. They remain clean and focused on their core logic, significantly improving maintainability.

- **Updated Tool Schemas**: The tool schemas in `index.ts` are now dynamically extended to include the optional `GITHUB_PERSONAL_ACCESS_TOKEN` parameter, without altering the base schemas in the `operations` files.

## Modified Files

- `common/context.ts` (New file)
- `common/utils.ts`
- `index.ts`