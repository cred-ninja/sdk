# Demonstrates: LangChain agent accesses GitHub via Cred.
# Token is delegated, not hardcoded.
#
# The agent defines a tool that delegates GitHub auth to Cred,
# then uses the short-lived token to hit the GitHub API.

import os
import requests
from cred_sdk import CredClient
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_openai import ChatOpenAI

cred = CredClient(
    server_url=os.environ.get("CRED_SERVER_URL", "http://localhost:3000"),
    agent_token=os.environ["CRED_AGENT_TOKEN"],
)


def list_github_repos(query: str = "") -> str:
    """List the authenticated user's GitHub repositories."""
    credential = cred.delegate("github")

    res = requests.get(
        "https://api.github.com/user/repos",
        headers={
            "Authorization": f"Bearer {credential.access_token}",
            "Accept": "application/vnd.github+json",
        },
        params={"sort": "updated", "per_page": 10},
    )
    res.raise_for_status()

    repos = res.json()
    if not repos:
        return "No repositories found."

    lines = [f"Found {len(repos)} repos:"]
    for r in repos:
        stars = r.get("stargazers_count", 0)
        lines.append(f"  {r['full_name']} ⭐ {stars}")
    return "\n".join(lines)


github_tool = Tool(
    name="list_repos",
    description="List the user's GitHub repositories via Cred-delegated token.",
    func=list_github_repos,
)

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

from langchain.prompts import PromptTemplate

prompt = PromptTemplate.from_template(
    "You are a helpful assistant with access to GitHub.\n\n"
    "Tools: {tools}\nTool names: {tool_names}\n\n"
    "{agent_scratchpad}\n\nUser: {input}"
)

agent = create_react_agent(llm, [github_tool], prompt)
executor = AgentExecutor(agent=agent, tools=[github_tool], verbose=True)

if __name__ == "__main__":
    result = executor.invoke({"input": "List my GitHub repos"})
    print(result["output"])
