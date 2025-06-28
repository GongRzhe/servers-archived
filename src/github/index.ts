#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';
import fetch from 'node-fetch';
import express from 'express';
import { randomUUID } from 'node:crypto';
import crypto from 'crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import {
  isInitializeRequest,
} from "@modelcontextprotocol/sdk/types.js";

import * as repository from './operations/repository.js';
import * as files from './operations/files.js';
import * as issues from './operations/issues.js';
import * as pulls from './operations/pulls.js';
import * as branches from './operations/branches.js';
import * as search from './operations/search.js';
import * as commits from './operations/commits.js';
import {
  GitHubError,
  GitHubValidationError,
  GitHubResourceNotFoundError,
  GitHubAuthenticationError,
  GitHubPermissionError,
  GitHubRateLimitError,
  GitHubConflictError,
  isGitHubError,
} from './common/errors.js';
import { VERSION } from "./common/version.js";
import { authStorage } from "./common/context.js";

// If fetch doesn't exist in global scope, add it
if (!globalThis.fetch) {
  globalThis.fetch = fetch as unknown as typeof global.fetch;
}

// Define the shape of the context for each request
interface AppContext {
    token: string | null;
    sessionId?: string;
    userId?: string;
}

// Create a new AsyncLocalStorage instance with the defined type
const asyncLocalStorage = new AsyncLocalStorage<AppContext>();

// Session management for multi-user support with token-based authentication
interface SessionData {
    token: string;
    userId?: string;
    sessionToken?: string;
    tokenCreatedAt?: Date;
}

const sessionStore = new Map<string, SessionData>();
const tokenToSessionMap = new Map<string, string>(); // Maps tokens to session IDs

// Global variable to track current request context (temporary solution)
let currentRequestContext: { mcpSessionId?: string; authSessionId?: string } = {};

// Helper function to get transport session ID from request context
function getTransportSessionId(): string | undefined {
    return currentRequestContext.mcpSessionId;
}

// Helper function to get or create session ID
function getCurrentSessionId(): string {
    const store = asyncLocalStorage.getStore();
    if (store?.sessionId) {
        return store.sessionId;
    }

    // Try to get from current request context
    if (currentRequestContext.authSessionId) {
        return currentRequestContext.authSessionId;
    }

    // Try to get from MCP transport
    const transportSessionId = getTransportSessionId();
    if (transportSessionId) {
        return 'auth-' + transportSessionId;
    }

    // Generate a new session ID if none exists
    return 'session-' + Date.now().toString(36) + Math.random().toString(36).substring(2);
}

// Helper function to generate a secure session token
function generateSessionToken(): string {
    return 'mcp_token_' + crypto.randomUUID().replace(/-/g, '') + '_' + Date.now().toString(36);
}

// Helper function to store session data with token
function storeSessionData(sessionId: string, token: string, userId?: string): string {
    const sessionToken = generateSessionToken();
    const sessionData: SessionData = {
        token,
        userId,
        sessionToken,
        tokenCreatedAt: new Date()
    };

    sessionStore.set(sessionId, sessionData);
    tokenToSessionMap.set(sessionToken, sessionId);

    console.log(`Stored session data for: ${sessionId} (user: ${userId || 'auto'}) with token: ${sessionToken.substring(0, 20)}...`);
    return sessionToken;
}

// Helper function to get session data
function getSessionData(sessionId: string): SessionData | undefined {
    const data = sessionStore.get(sessionId);
    if (data) {
        console.log(`Retrieved session data for: ${sessionId} (user: ${data.userId || 'auto'})`);
    }
    return data;
}

// Helper function to validate session token
function validateSessionToken(token: string): { sessionId: string; sessionData: SessionData } | null {
    const sessionId = tokenToSessionMap.get(token);
    if (!sessionId) {
        console.log(`Invalid token provided: ${token.substring(0, 20)}...`);
        return null;
    }

    const sessionData = sessionStore.get(sessionId);
    if (!sessionData || sessionData.sessionToken !== token) {
        console.log(`Token mismatch for session: ${sessionId}`);
        return null;
    }

    // Check if token is expired (24 hours)
    const tokenAge = Date.now() - (sessionData.tokenCreatedAt?.getTime() || 0);
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    if (tokenAge > maxAge) {
        console.log(`Token expired for session: ${sessionId}`);
        // Clean up expired token
        tokenToSessionMap.delete(token);
        sessionStore.delete(sessionId);
        return null;
    }

    console.log(`Valid token verified for session: ${sessionId} (user: ${sessionData.userId || 'auto'})`);
    return { sessionId, sessionData };
}

const server = new Server(
  {
    name: "github-mcp-server",
    version: VERSION,
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

function formatGitHubError(error: GitHubError): string {
  let message = `GitHub API Error: ${error.message}`;
  
  if (error instanceof GitHubValidationError) {
    message = `Validation Error: ${error.message}`;
    if (error.response) {
      message += `\nDetails: ${JSON.stringify(error.response)}`;
    }
  } else if (error instanceof GitHubResourceNotFoundError) {
    message = `Not Found: ${error.message}`;
  } else if (error instanceof GitHubAuthenticationError) {
    message = `Authentication Failed: ${error.message}`;
  } else if (error instanceof GitHubPermissionError) {
    message = `Permission Denied: ${error.message}`;
  } else if (error instanceof GitHubRateLimitError) {
    message = `Rate Limit Exceeded: ${error.message}\nResets at: ${error.resetAt.toISOString()}`;
  } else if (error instanceof GitHubConflictError) {
    message = `Conflict: ${error.message}`;
  }

  return message;
}

const GITHUB_PERSONAL_ACCESS_TOKEN = {
    GITHUB_PERSONAL_ACCESS_TOKEN: z.string().optional().describe("GitHub Personal Access Token"),
};

const GITHUB_AUTH_SCHEMA = {
    GITHUB_PERSONAL_ACCESS_TOKEN: z.string().optional().describe("GitHub Personal Access Token"),
    sessionToken: z.string().optional().describe("Session token for authenticated requests (use instead of GITHUB_PERSONAL_ACCESS_TOKEN after initial authentication)"),
};

// Empty schema for tools that don't need authentication parameters (session-based auth)
const NO_AUTH_SCHEMA = {};

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "create_or_update_file",
        description: "Create or update a single file in a GitHub repository",
        inputSchema: zodToJsonSchema(files.CreateOrUpdateFileSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "search_repositories",
        description: "Search for GitHub repositories",
        inputSchema: zodToJsonSchema(repository.SearchRepositoriesSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "create_repository",
        description: "Create a new GitHub repository in your account",
        inputSchema: zodToJsonSchema(repository.CreateRepositoryOptionsSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "get_file_contents",
        description: "Get the contents of a file or directory from a GitHub repository",
        inputSchema: zodToJsonSchema(files.GetFileContentsSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "push_files",
        description: "Push multiple files to a GitHub repository in a single commit",
        inputSchema: zodToJsonSchema(files.PushFilesSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "create_issue",
        description: "Create a new issue in a GitHub repository",
        inputSchema: zodToJsonSchema(issues.CreateIssueSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "create_pull_request",
        description: "Create a new pull request in a GitHub repository",
        inputSchema: zodToJsonSchema(pulls.CreatePullRequestSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "fork_repository",
        description: "Fork a GitHub repository to your account or specified organization",
        inputSchema: zodToJsonSchema(repository.ForkRepositorySchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "create_branch",
        description: "Create a new branch in a GitHub repository",
        inputSchema: zodToJsonSchema(branches.CreateBranchSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "list_commits",
        description: "Get list of commits of a branch in a GitHub repository",
        inputSchema: zodToJsonSchema(commits.ListCommitsSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "list_issues",
        description: "List issues in a GitHub repository with filtering options",
        inputSchema: zodToJsonSchema(issues.ListIssuesOptionsSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "update_issue",
        description: "Update an existing issue in a GitHub repository",
        inputSchema: zodToJsonSchema(issues.UpdateIssueOptionsSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "add_issue_comment",
        description: "Add a comment to an existing issue",
        inputSchema: zodToJsonSchema(issues.IssueCommentSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "search_code",
        description: "Search for code across GitHub repositories",
        inputSchema: zodToJsonSchema(search.SearchCodeSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "search_issues",
        description: "Search for issues and pull requests across GitHub repositories",
        inputSchema: zodToJsonSchema(search.SearchIssuesSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "search_users",
        description: "Search for users on GitHub",
        inputSchema: zodToJsonSchema(search.SearchUsersSchema.extend(NO_AUTH_SCHEMA)),
      },
      {
        name: "get_issue",
        description: "Get details of a specific issue in a GitHub repository.",
        inputSchema: zodToJsonSchema(issues.GetIssueSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "get_pull_request",
        description: "Get details of a specific pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "list_pull_requests",
        description: "List and filter repository pull requests",
        inputSchema: zodToJsonSchema(pulls.ListPullRequestsSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "create_pull_request_review",
        description: "Create a review on a pull request",
        inputSchema: zodToJsonSchema(pulls.CreatePullRequestReviewSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "merge_pull_request",
        description: "Merge a pull request",
        inputSchema: zodToJsonSchema(pulls.MergePullRequestSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "get_pull_request_files",
        description: "Get the list of files changed in a pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestFilesSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "get_pull_request_status",
        description: "Get the combined status of all status checks for a pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestStatusSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "update_pull_request_branch",
        description: "Update a pull request branch with the latest changes from the base branch",
        inputSchema: zodToJsonSchema(pulls.UpdatePullRequestBranchSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "get_pull_request_comments",
        description: "Get the review comments on a pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestCommentsSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "get_pull_request_reviews",
        description: "Get the reviews on a pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestReviewsSchema.extend(NO_AUTH_SCHEMA))
      },
      {
        name: "validate_token",
        description: "Validate if the provided GitHub token is valid and get user information",
        inputSchema: zodToJsonSchema(z.object(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "authenticate_with_token",
        description: "Authenticate using a previously received session token",
        inputSchema: zodToJsonSchema(z.object({
          sessionToken: z.string().describe("Session token received after successful authentication")
        }))
      }
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  // Get the current session ID for this request
  const sessionId = getCurrentSessionId();
  
  return await asyncLocalStorage.run({ token: null, sessionId }, async () => {
    try {
      if (!request.params.arguments) {
        throw new Error("Arguments are required");
      }

      const { GITHUB_PERSONAL_ACCESS_TOKEN, sessionToken, ...args } = request.params.arguments;
      const store = asyncLocalStorage.getStore();
      let token: string | undefined;

      // For validate_token and authenticate_with_token, handle authentication parameters
      if (request.params.name === 'validate_token' || request.params.name === 'authenticate_with_token') {
        if (request.params.name === 'validate_token') {
          // Extract GitHub token for validation
          token = typeof GITHUB_PERSONAL_ACCESS_TOKEN === 'string' ? GITHUB_PERSONAL_ACCESS_TOKEN : undefined;
        } else {
          // For authenticate_with_token, extract session token
          const providedSessionToken = typeof sessionToken === 'string' ? sessionToken : undefined;
          if (providedSessionToken) {
            const tokenValidation = validateSessionToken(providedSessionToken);
            if (tokenValidation) {
              token = tokenValidation.sessionData.token;
              // Update current session context
              if (store) {
                store.token = token;
                store.userId = tokenValidation.sessionData.userId;
              }
            }
          }
        }
      } else {
        // For all other tools, check if we have stored authentication in the session
        const sessionData = getSessionData(sessionId);
        if (sessionData) {
          token = sessionData.token;
          if (store) {
            store.token = token;
            store.userId = sessionData.userId;
          }
          console.log(`Using stored authentication for session: ${sessionId} (user: ${sessionData.userId || 'auto'})`);
        } else {
          // No stored authentication, require authentication
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                error: "Authentication required for this session",
                message: "Please authenticate first using one of the following methods:",
                authentication_methods: [
                  {
                    method: "Session Authentication",
                    description: "Call validate_token with your GitHub token to authenticate this session",
                    step: "Once authenticated, all subsequent requests in this session will be automatically authenticated"
                  },
                  {
                    method: "Token Authentication",
                    description: "Call authenticate_with_token with a valid session token",
                    step: "This will authenticate the current session using a previously obtained session token"
                  }
                ],
                session_id: sessionId,
                next_steps: [
                  `Call validate_token with your GITHUB_PERSONAL_ACCESS_TOKEN to authenticate session ${sessionId}`,
                  "All subsequent tool calls in this session will be automatically authenticated"
                ]
              }, null, 2)
            }],
          };
        }
      }

      return await authStorage.run({ token }, async () => {
        switch (request.params.name) {
        case "fork_repository": {
            const parsedArgs = repository.ForkRepositorySchema.parse(args);
            const fork = await repository.forkRepository(parsedArgs.owner, parsedArgs.repo, parsedArgs.organization);
            return {
            content: [{ type: "text", text: JSON.stringify(fork, null, 2) }],
            };
        }

        case "create_branch": {
            const parsedArgs = branches.CreateBranchSchema.parse(args);
            const branch = await branches.createBranchFromRef(
            parsedArgs.owner,
            parsedArgs.repo,
            parsedArgs.branch,
            parsedArgs.from_branch
            );
            return {
            content: [{ type: "text", text: JSON.stringify(branch, null, 2) }],
            };
        }

        case "search_repositories": {
            const parsedArgs = repository.SearchRepositoriesSchema.parse(args);
            const results = await repository.searchRepositories(
            parsedArgs.query,
            parsedArgs.page,
            parsedArgs.perPage
            );
            return {
            content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
            };
        }

        case "create_repository": {
            const parsedArgs = repository.CreateRepositoryOptionsSchema.parse(args);
            const result = await repository.createRepository(parsedArgs);
            return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
        }

        case "get_file_contents": {
            const parsedArgs = files.GetFileContentsSchema.parse(args);
            const contents = await files.getFileContents(
            parsedArgs.owner,
            parsedArgs.repo,
            parsedArgs.path,
            parsedArgs.branch
            );
            return {
            content: [{ type: "text", text: JSON.stringify(contents, null, 2) }],
            };
        }

        case "create_or_update_file": {
            const parsedArgs = files.CreateOrUpdateFileSchema.parse(args);
            const result = await files.createOrUpdateFile(
            parsedArgs.owner,
            parsedArgs.repo,
            parsedArgs.path,
            parsedArgs.content,
            parsedArgs.message,
            parsedArgs.branch,
            parsedArgs.sha
            );
            return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
        }

        case "push_files": {
            const parsedArgs = files.PushFilesSchema.parse(args);
            const result = await files.pushFiles(
            parsedArgs.owner,
            parsedArgs.repo,
            parsedArgs.branch,
            parsedArgs.files,
            parsedArgs.message
            );
            return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
        }

        case "create_issue": {
            const parsedArgs = issues.CreateIssueSchema.parse(args);
            const { owner, repo, ...options } = parsedArgs;
            
            try {
            console.error(`[DEBUG] Attempting to create issue in ${owner}/${repo}`);
            console.error(`[DEBUG] Issue options:`, JSON.stringify(options, null, 2));
            
            const issue = await issues.createIssue(owner, repo, options);
            
            console.error(`[DEBUG] Issue created successfully`);
            return {
                content: [{ type: "text", text: JSON.stringify(issue, null, 2) }],
            };
            } catch (err) {
            // Type guard for Error objects
            const error = err instanceof Error ? err : new Error(String(err));
            
            console.error(`[ERROR] Failed to create issue:`, error);
            
            if (error instanceof GitHubResourceNotFoundError) {
                throw new Error(
                `Repository '${owner}/${repo}' not found. Please verify:\n` +
                `1. The repository exists\n` +
                `2. You have correct access permissions\n` +
                `3. The owner and repository names are spelled correctly`
                );
            }
            
            // Safely access error properties
            throw new Error(
                `Failed to create issue: ${error.message}${error.stack ? `\nStack: ${error.stack}` : ''}`
            );
            }
        }

        case "create_pull_request": {
            const parsedArgs = pulls.CreatePullRequestSchema.parse(args);
            const pullRequest = await pulls.createPullRequest(parsedArgs);
            return {
            content: [{ type: "text", text: JSON.stringify(pullRequest, null, 2) }],
            };
        }

        case "search_code": {
            const parsedArgs = search.SearchCodeSchema.parse(args);
            const results = await search.searchCode(parsedArgs);
            return {
            content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
            };
        }

        case "search_issues": {
            const parsedArgs = search.SearchIssuesSchema.parse(args);
            const results = await search.searchIssues(parsedArgs);
            return {
            content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
            };
        }

        case "search_users": {
            const parsedArgs = search.SearchUsersSchema.parse(args);
            const results = await search.searchUsers(parsedArgs);
            return {
            content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
            };
        }

        case "list_issues": {
            const parsedArgs = issues.ListIssuesOptionsSchema.parse(args);
            const { owner, repo, ...options } = parsedArgs;
            const result = await issues.listIssues(owner, repo, options);
            return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
        }

        case "update_issue": {
            const parsedArgs = issues.UpdateIssueOptionsSchema.parse(args);
            const { owner, repo, issue_number, ...options } = parsedArgs;
            const result = await issues.updateIssue(owner, repo, issue_number, options);
            return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
        }

        case "add_issue_comment": {
            const parsedArgs = issues.IssueCommentSchema.parse(args);
            const { owner, repo, issue_number, body } = parsedArgs;
            const result = await issues.addIssueComment(owner, repo, issue_number, body);
            return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
        }

        case "list_commits": {
            const parsedArgs = commits.ListCommitsSchema.parse(args);
            const results = await commits.listCommits(
            parsedArgs.owner,
            parsedArgs.repo,
            parsedArgs.page,
            parsedArgs.perPage,
            parsedArgs.sha
            );
            return {
            content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
            };
        }

        case "get_issue": {
            const parsedArgs = issues.GetIssueSchema.parse(args);
            const issue = await issues.getIssue(parsedArgs.owner, parsedArgs.repo, parsedArgs.issue_number);
            return {
            content: [{ type: "text", text: JSON.stringify(issue, null, 2) }],
            };
        }

        case "get_pull_request": {
            const parsedArgs = pulls.GetPullRequestSchema.parse(args);
            const pullRequest = await pulls.getPullRequest(parsedArgs.owner, parsedArgs.repo, parsedArgs.pull_number);
            return {
            content: [{ type: "text", text: JSON.stringify(pullRequest, null, 2) }],
            };
        }

        case "list_pull_requests": {
            const parsedArgs = pulls.ListPullRequestsSchema.parse(args);
            const { owner, repo, ...options } = parsedArgs;
            const pullRequests = await pulls.listPullRequests(owner, repo, options);
            return {
            content: [{ type: "text", text: JSON.stringify(pullRequests, null, 2) }],
            };
        }

        case "create_pull_request_review": {
            const parsedArgs = pulls.CreatePullRequestReviewSchema.parse(args);
            const { owner, repo, pull_number, ...options } = parsedArgs;
            const review = await pulls.createPullRequestReview(owner, repo, pull_number, options);
            return {
            content: [{ type: "text", text: JSON.stringify(review, null, 2) }],
            };
        }

        case "merge_pull_request": {
            const parsedArgs = pulls.MergePullRequestSchema.parse(args);
            const { owner, repo, pull_number, ...options } = parsedArgs;
            const result = await pulls.mergePullRequest(owner, repo, pull_number, options);
            return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
        }

        case "get_pull_request_files": {
            const parsedArgs = pulls.GetPullRequestFilesSchema.parse(args);
            const files = await pulls.getPullRequestFiles(parsedArgs.owner, parsedArgs.repo, parsedArgs.pull_number);
            return {
            content: [{ type: "text", text: JSON.stringify(files, null, 2) }],
            };
        }

        case "get_pull_request_status": {
            const parsedArgs = pulls.GetPullRequestStatusSchema.parse(args);
            const status = await pulls.getPullRequestStatus(parsedArgs.owner, parsedArgs.repo, parsedArgs.pull_number);
            return {
            content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
            };
        }

        case "update_pull_request_branch": {
            const parsedArgs = pulls.UpdatePullRequestBranchSchema.parse(args);
            const { owner, repo, pull_number, expected_head_sha } = parsedArgs;
            await pulls.updatePullRequestBranch(owner, repo, pull_number, expected_head_sha);
            return {
            content: [{ type: "text", text: JSON.stringify({ success: true }, null, 2) }],
            };
        }

        case "get_pull_request_comments": {
            const parsedArgs = pulls.GetPullRequestCommentsSchema.parse(args);
            const comments = await pulls.getPullRequestComments(parsedArgs.owner, parsedArgs.repo, parsedArgs.pull_number);
            return {
            content: [{ type: "text", text: JSON.stringify(comments, null, 2) }],
            };
        }

        case "get_pull_request_reviews": {
            const parsedArgs = pulls.GetPullRequestReviewsSchema.parse(args);
            const reviews = await pulls.getPullRequestReviews(parsedArgs.owner, parsedArgs.repo, parsedArgs.pull_number);
            return {
            content: [{ type: "text", text: JSON.stringify(reviews, null, 2) }],
            };
        }

        case "validate_token": {
            
            if (!token) {
                return {
                    content: [{ 
                        type: "text", 
                        text: JSON.stringify({
                            valid: false,
                            error: "No GitHub token provided",
                            message: "Please provide a GITHUB_PERSONAL_ACCESS_TOKEN parameter"
                        }, null, 2) 
                    }],
                };
            }

            try {
                // Use GitHub API to validate token by getting authenticated user info
                const response = await fetch('https://api.github.com/user', {
                    headers: {
                        'Authorization': `token ${token}`,
                        'User-Agent': 'GitHub-MCP-Server',
                        'Accept': 'application/vnd.github.v3+json'
                    }
                });

                if (response.ok) {
                    const userData = await response.json() as any;
                    
                    // Get token scopes from headers
                    const scopes = response.headers.get('x-oauth-scopes') || '';
                    
                    // Store authentication in current session and generate session token
                    const store = asyncLocalStorage.getStore();
                    const currentSessionId = store?.sessionId || getCurrentSessionId();
                    const sessionToken = storeSessionData(currentSessionId, token, userData.login);
                    
                    // Update current session store
                    if (store) {
                        store.token = token;
                        store.userId = userData.login;
                    }
                    
                    return {
                        content: [{ 
                            type: "text", 
                            text: JSON.stringify({
                                valid: true,
                                user: {
                                    login: userData.login,
                                    id: userData.id,
                                    name: userData.name,
                                    email: userData.email,
                                    avatar_url: userData.avatar_url,
                                    public_repos: userData.public_repos,
                                    private_repos: userData.total_private_repos,
                                    plan: userData.plan?.name
                                },
                                token_info: {
                                    scopes: scopes.split(',').map((s: string) => s.trim()).filter(Boolean),
                                    rate_limit_remaining: response.headers.get('x-ratelimit-remaining'),
                                    rate_limit_reset: response.headers.get('x-ratelimit-reset')
                                },
                                session: {
                                    session_id: currentSessionId,
                                    session_token: sessionToken,
                                    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
                                    message: "🎉 Authentication successful! This session is now authenticated. All subsequent requests in this session will automatically use your GitHub token.",
                                    note: "You can also use the session_token with authenticate_with_token in other sessions or save it for later use."
                                }
                            }, null, 2) 
                        }],
                    };
                } else {
                    const errorData = await response.json().catch(() => ({})) as any;
                    return {
                        content: [{ 
                            type: "text", 
                            text: JSON.stringify({
                                valid: false,
                                error: `GitHub API Error: ${response.status} ${response.statusText}`,
                                message: errorData.message || "Invalid token or insufficient permissions",
                                documentation_url: errorData.documentation_url
                            }, null, 2) 
                        }],
                    };
                }
            } catch (error: any) {
                return {
                    content: [{ 
                        type: "text", 
                        text: JSON.stringify({
                            valid: false,
                            error: "Network or parsing error",
                            message: error.message
                        }, null, 2) 
                    }],
                };
            }
        }

        case "authenticate_with_token": {
            const args = request.params.arguments;
            const providedToken = args?.sessionToken as string;

            if (!providedToken) {
                return {
                    content: [{
                        type: "text",
                        text: JSON.stringify({
                            authenticated: false,
                            error: "No session token provided",
                            message: "Please provide a sessionToken parameter"
                        }, null, 2)
                    }],
                };
            }

            const tokenValidation = validateSessionToken(providedToken);

            if (!tokenValidation) {
                return {
                    content: [{
                        type: "text",
                        text: JSON.stringify({
                            authenticated: false,
                            error: "Invalid or expired session token",
                            message: "Please authenticate again using validate_token with your GitHub token"
                        }, null, 2)
                    }],
                };
            }

            // Store authentication in current session and update context
            const store = asyncLocalStorage.getStore();
            const currentSessionId = store?.sessionId || getCurrentSessionId();
            
            if (store && tokenValidation) {
                store.token = tokenValidation.sessionData.token;
                store.userId = tokenValidation.sessionData.userId;
            }
            
            // Store authentication data in current session for future requests
            storeSessionData(currentSessionId, tokenValidation.sessionData.token, tokenValidation.sessionData.userId);

            const expiryDate = tokenValidation.sessionData.tokenCreatedAt
                ? new Date(tokenValidation.sessionData.tokenCreatedAt.getTime() + 24 * 60 * 60 * 1000).toLocaleString()
                : 'Unknown';

            return {
                content: [{
                    type: "text",
                    text: JSON.stringify({
                        authenticated: true,
                        user: tokenValidation.sessionData.userId || 'auto-detected',
                        current_session: currentSessionId,
                        original_session: tokenValidation.sessionId,
                        token_valid_until: expiryDate,
                        message: "✅ Authentication successful! This session is now authenticated. All subsequent requests in this session will automatically use your stored GitHub token."
                    }, null, 2)
                }],
            };
        }

        default:
            throw new Error(`Unknown tool: ${request.params.name}`);
        }
      });
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`Invalid input: ${JSON.stringify(error.errors)}`);
    }
    if (isGitHubError(error)) {
      throw new Error(formatGitHubError(error));
    }
    throw error;
  }
  }); // Close asyncLocalStorage.run callback
}); // Close server.setRequestHandler

// HTTP/SSE server setup function
async function startHttpServer(mcpServer: Server, transportMode: 'http' | 'sse') {
  const app = express();
  app.use(express.json());

  console.log(`Starting GitHub MCP Server with ${transportMode.toUpperCase()} transport...`);

  // Store transports for session management
  const transports = {
    streamable: {} as Record<string, StreamableHTTPServerTransport>,
    sse: {} as Record<string, SSEServerTransport>
  };

  if (transportMode === 'http') {
    // Modern Streamable HTTP endpoint
    app.all('/mcp', async (req, res) => {
      try {
        // Set CORS headers
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, mcp-session-id');

        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;

        if (sessionId && transports.streamable[sessionId]) {
          // Reuse existing transport
          transport = transports.streamable[sessionId];
        } else if (!sessionId && req.method === 'POST' && isInitializeRequest(req.body)) {
          // New initialization request
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sessionId: string) => {
              transports.streamable[sessionId] = transport;
              console.log(`New session initialized: ${sessionId}`);
            }
          });

          // Clean up transport when closed
          transport.onclose = () => {
            if (transport.sessionId) {
              delete transports.streamable[transport.sessionId];
              console.log(`Session closed: ${transport.sessionId}`);
            }
          };

          // Connect the server to the transport
          await mcpServer.connect(transport);
        } else if (req.method === 'POST') {
          // POST request without session ID for non-initialize requests
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: 'Bad Request: Session ID required for non-initialize requests',
            },
            id: req.body.id || null,
          });
          return;
        } else {
          // Other methods (GET/DELETE) require session ID
          if (!sessionId || !transports.streamable[sessionId]) {
            res.status(400).send('Invalid or missing session ID');
            return;
          }
          transport = transports.streamable[sessionId];
        }

        // Set current request context before handling
        const mcpSessionId = transport.sessionId || sessionId;
        const authSessionId = 'auth-' + (mcpSessionId || 'default');

        currentRequestContext = { mcpSessionId, authSessionId };

        try {
          // Handle the request through the proper MCP transport
          await transport.handleRequest(req, res, req.body);
        } finally {
          // Clear request context
          currentRequestContext = {};
        }

      } catch (error: any) {
        console.error('Error handling Streamable HTTP request:', error);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: {
              code: -32603,
              message: 'Internal server error',
            },
            id: null,
          });
        }
      }
    });
  }

  if (transportMode === 'sse') {
    // SSE endpoint
    app.get('/sse', async (req, res) => {
      try {
        const transport = new SSEServerTransport('/messages', res);
        transports.sse[transport.sessionId] = transport;

        res.on("close", () => {
          delete transports.sse[transport.sessionId];
          console.log(`SSE session closed: ${transport.sessionId}`);
        });

        await mcpServer.connect(transport);
        console.log(`SSE session started: ${transport.sessionId}`);
      } catch (error) {
        console.error('Error starting SSE transport:', error);
        res.status(500).send('Failed to start SSE transport');
      }
    });

    // Message endpoint for SSE clients
    app.post('/messages', async (req, res) => {
      try {
        const sessionId = req.query.sessionId as string;
        const transport = transports.sse[sessionId];
        if (transport) {
          await transport.handlePostMessage(req, res, req.body);
        } else {
          res.status(400).send('No transport found for sessionId');
        }
      } catch (error) {
        console.error('Error handling SSE message:', error);
        res.status(500).send('Error processing message');
      }
    });
  }

  // Handle CORS preflight for all endpoints
  app.options('*', (req, res) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, mcp-session-id');
    res.sendStatus(200);
  });

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      transport: transportMode,
      timestamp: new Date().toISOString(),
      version: VERSION,
      activeSessions: {
        streamable: Object.keys(transports.streamable).length,
        sse: Object.keys(transports.sse).length
      }
    });
  });

  // API documentation endpoint
  app.get('/', (req, res) => {
    res.json({
      name: 'GitHub MCP Server',
      version: VERSION,
      transport: transportMode,
      protocol: transportMode === 'http' ? 'Streamable HTTP (2025-03-26)' : 'SSE (deprecated)',
      endpoints: transportMode === 'http' ? {
        mcp: 'ALL /mcp - MCP Streamable HTTP endpoint',
        health: 'GET /health - Health check'
      } : {
        sse: 'GET /sse - SSE connection endpoint',
        messages: 'POST /messages - Message handling endpoint',
        health: 'GET /health - Health check'
      },
      documentation: 'https://modelcontextprotocol.io/docs'
    });
  });

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`GitHub MCP Server listening on port ${port}`);
    console.log(`Transport mode: ${transportMode}`);
    if (transportMode === 'http') {
      console.log(`Streamable HTTP endpoint: http://localhost:${port}/mcp`);
    } else {
      console.log(`SSE endpoint: http://localhost:${port}/sse`);
      console.log(`Messages endpoint: http://localhost:${port}/messages`);
    }
    console.log(`Health check: http://localhost:${port}/health`);
    console.log(`Documentation: http://localhost:${port}/`);
  });
}

async function runServer() {
  // Determine transport mode from command line arguments
  const transportMode = process.argv.includes('--http') ? 'http' :
    process.argv.includes('--sse') ? 'sse' : 'stdio';

  if (transportMode === 'stdio') {
    // Default stdio transport
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("GitHub MCP Server running on stdio");
  } else {
    // HTTP or SSE transport - start Express server
    await startHttpServer(server, transportMode as 'http' | 'sse');
  }
}

runServer().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});