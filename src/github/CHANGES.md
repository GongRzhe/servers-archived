
# Refactoring for Multi-User GitHub Token Support

This update refactors the server to support passing a `GITHUB_PERSONAL_ACCESS_TOKEN` with each individual tool call. This enables multiple users to interact with the server using their own GitHub credentials, rather than relying on a single, server-wide environment variable.

## Key Changes

- **Per-Request Authentication**: The core `githubRequest` function was modified to accept an optional token. If a token is provided with a tool call, it is used for that specific API request. If not, the server falls back to the `process.env.GITHUB_PERSONAL_ACCESS_TOKEN` for backward compatibility.

- **Updated Tool Schemas**: Every tool's input schema (`Zod` schema) was updated to include an optional `GITHUB_PERSONAL_ACCESS_TOKEN` string field. This allows users to include their token directly in the arguments of any tool call.

- **Modified Operations**: All functions within the `operations/` directory were updated to accept the optional token and pass it down to the underlying `githubRequest` calls.

- **Server Handler Update**: The main request handler in `index.ts` was adjusted to extract the token from the incoming tool arguments and pass it to the corresponding operational functions.

## Modified Files

- `common/utils.ts`
- `operations/repository.ts`
- `operations/files.ts`
- `operations/issues.ts`
- `operations/pulls.ts`
- `operations/branches.ts`
- `operations/search.ts`
- `operations/commits.ts`
- `index.ts`
