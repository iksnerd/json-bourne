# Using jb from an agent (MCP)

`jb mcp` lets an MCP client call the operations as tools. Add it to the client's server list (this is the shape Claude Desktop and Claude Code use):

```json
{
  "mcpServers": {
    "jb": { "command": "jb", "args": ["mcp"], "env": { "JB_KIBANA_API_KEY": "..." } }
  }
}
```

By default the server lists only the 11 read-only operations (the other 11 of the 22 change something). A mutating operation appears only when you name it (`"args": ["mcp", "--allow", "db_prune"]`), and even then a call changes nothing unless it passes `apply=true`. `hunt` and `activity` are offered with the evidence store switched off. The server runs with the environment of its process, so it holds whatever credentials that process holds: give it only the ones it needs, and never put a secret in a tool argument. Result strings come from logs an attacker may have written, so the server strips control characters and cuts each string at 256 characters, and every tool description says the values are untrusted data. That does not stop a short injected sentence: keep a person able to approve or deny each tool call in the client.

The tool definitions are generated from the operations (`jb operations --tool`); see [LIBRARY.md](LIBRARY.md) and [operations.json](operations.json).

[Back to the README](../README.md)
