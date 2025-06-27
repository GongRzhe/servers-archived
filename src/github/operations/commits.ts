import { z } from "zod";
import { githubRequest, buildUrl } from "../common/utils.js";

export const ListCommitsSchema = z.object({
  owner: z.string(),
  repo: z.string(),
  sha: z.string().optional(),
  page: z.number().optional(),
  perPage: z.number().optional(),
  GITHUB_PERSONAL_ACCESS_TOKEN: z.string().optional().describe("GitHub Personal Access Token"),
});

export async function listCommits(
  owner: string,
  repo: string,
  page?: number,
  perPage?: number,
  sha?: string,
  token?: string,
) {
  return githubRequest(
    buildUrl(`https://api.github.com/repos/${owner}/${repo}/commits`, {
      page: page,
      per_page: perPage,
      sha
    }),
    {},
    token,
  );
}