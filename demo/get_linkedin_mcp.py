from composio import Composio

composio = Composio(api_key="ak_-NPqA3jMn36Fm_KZSIp2")

session = composio.create(
    user_id="prerak-job-hunt",
    toolkits=["linkedin"]
)

mcp_url = session.mcp.url
print("Your MCP URL:")
print(mcp_url)
