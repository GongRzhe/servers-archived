import { z } from "zod";
import { githubRequest, buildUrl } from "../common/utils.js";

export const SearchOptions = z.object({
  q: z.string(),
  order: z.enum(["asc", "desc"]).optional(),
  page: z.number().min(1).optional(),
  per_page: z.number().min(1).max(100).optional(),
  GITHUB_PERSONAL_ACCESS_TOKEN: z.string().optional().describe("GitHub Personal Access Token"),
});

export const SearchUsersOptions = SearchOptions.extend({
  sort: z.enum(["followers", "repositories", "joined"]).optional(),
});

export const SearchIssuesOptions = SearchOptions.extend({
  sort: z.enum([
    "comments",
    "reactions",
    "reactions-+1",
    "reactions--1",
    "reactions-smile",
    "reactions-thinking_face",
    "reactions-heart",
    "reactions-tada",
    "interactions",
    "created",
    "updated",
  ]).optional(),
});

export const SearchCodeSchema = SearchOptions;
export const SearchUsersSchema = SearchUsersOptions;
export const SearchIssuesSchema = SearchIssuesOptions;

export async function searchCode(params: z.infer<typeof SearchCodeSchema>) {
  const { GITHUB_PERSONAL_ACCESS_TOKEN, ...rest } = params;
  return githubRequest(buildUrl("https://api.github.com/search/code", rest), {}, GITHUB_PERSONAL_ACCESS_TOKEN);
}

export async function searchIssues(params: z.infer<typeof SearchIssuesSchema>) {
  const { GITHUB_PERSONAL_ACCESS_TOKEN, ...rest } = params;
  return githubRequest(buildUrl("https://api.github.com/search/issues", rest), {}, GITHUB_PERSONAL_ACCESS_TOKEN);
}

export async function searchUsers(params: z.infer<typeof SearchUsersSchema>) {
    const { GITHUB_PERSONAL_ACCESS_TOKEN, ...rest } = params;
  return githubRequest(buildUrl("https://api.github.com/search/users", rest), {}, GITHUB_PERSONAL_ACCESS_TOKEN);
}