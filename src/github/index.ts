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

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "create_or_update_file",
        description: "Create or update a single file in a GitHub repository",
        inputSchema: zodToJsonSchema(files.CreateOrUpdateFileSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "search_repositories",
        description: "Search for GitHub repositories",
        inputSchema: zodToJsonSchema(repository.SearchRepositoriesSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "create_repository",
        description: "Create a new GitHub repository in your account",
        inputSchema: zodToJsonSchema(repository.CreateRepositoryOptionsSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "get_file_contents",
        description: "Get the contents of a file or directory from a GitHub repository",
        inputSchema: zodToJsonSchema(files.GetFileContentsSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "push_files",
        description: "Push multiple files to a GitHub repository in a single commit",
        inputSchema: zodToJsonSchema(files.PushFilesSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "create_issue",
        description: "Create a new issue in a GitHub repository",
        inputSchema: zodToJsonSchema(issues.CreateIssueSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "create_pull_request",
        description: "Create a new pull request in a GitHub repository",
        inputSchema: zodToJsonSchema(pulls.CreatePullRequestSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "fork_repository",
        description: "Fork a GitHub repository to your account or specified organization",
        inputSchema: zodToJsonSchema(repository.ForkRepositorySchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "create_branch",
        description: "Create a new branch in a GitHub repository",
        inputSchema: zodToJsonSchema(branches.CreateBranchSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "list_commits",
        description: "Get list of commits of a branch in a GitHub repository",
        inputSchema: zodToJsonSchema(commits.ListCommitsSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "list_issues",
        description: "List issues in a GitHub repository with filtering options",
        inputSchema: zodToJsonSchema(issues.ListIssuesOptionsSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "update_issue",
        description: "Update an existing issue in a GitHub repository",
        inputSchema: zodToJsonSchema(issues.UpdateIssueOptionsSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "add_issue_comment",
        description: "Add a comment to an existing issue",
        inputSchema: zodToJsonSchema(issues.IssueCommentSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "search_code",
        description: "Search for code across GitHub repositories",
        inputSchema: zodToJsonSchema(search.SearchCodeSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "search_issues",
        description: "Search for issues and pull requests across GitHub repositories",
        inputSchema: zodToJsonSchema(search.SearchIssuesSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "search_users",
        description: "Search for users on GitHub",
        inputSchema: zodToJsonSchema(search.SearchUsersSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN)),
      },
      {
        name: "get_issue",
        description: "Get details of a specific issue in a GitHub repository.",
        inputSchema: zodToJsonSchema(issues.GetIssueSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "get_pull_request",
        description: "Get details of a specific pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "list_pull_requests",
        description: "List and filter repository pull requests",
        inputSchema: zodToJsonSchema(pulls.ListPullRequestsSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "create_pull_request_review",
        description: "Create a review on a pull request",
        inputSchema: zodToJsonSchema(pulls.CreatePullRequestReviewSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "merge_pull_request",
        description: "Merge a pull request",
        inputSchema: zodToJsonSchema(pulls.MergePullRequestSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "get_pull_request_files",
        description: "Get the list of files changed in a pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestFilesSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "get_pull_request_status",
        description: "Get the combined status of all status checks for a pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestStatusSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "update_pull_request_branch",
        description: "Update a pull request branch with the latest changes from the base branch",
        inputSchema: zodToJsonSchema(pulls.UpdatePullRequestBranchSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "get_pull_request_comments",
        description: "Get the review comments on a pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestCommentsSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      },
      {
        name: "get_pull_request_reviews",
        description: "Get the reviews on a pull request",
        inputSchema: zodToJsonSchema(pulls.GetPullRequestReviewsSchema.extend(GITHUB_PERSONAL_ACCESS_TOKEN))
      }
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    if (!request.params.arguments) {
      throw new Error("Arguments are required");
    }

    const { GITHUB_PERSONAL_ACCESS_TOKEN, ...args } = request.params.arguments;

    const token = typeof GITHUB_PERSONAL_ACCESS_TOKEN === 'string' ? GITHUB_PERSONAL_ACCESS_TOKEN : undefined;

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
});

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

        // Handle the request through the proper MCP transport
        await transport.handleRequest(req, res, req.body);

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