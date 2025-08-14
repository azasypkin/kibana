# @kbn/uiam-dev-cli

The CLI that allows running UIAM service locally with the Cosmos DB emulator.

## Tools

You can access Cosmos DB emulator UI at [http://localhost:8082](http://localhost:8082/).

## Example requests
```shell
curl -X POST --location "http://localhost:8080/uiam/api/v1/authentication/_authenticate?include_token=true" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI5ODc2NTQzMjEiLCJuYmYiOjE3NTUxNzEzMDgsInJhcyI6eyJwbGF0Zm9ybSI6W3sicm9sZV9pZCI6ImVzcy1kZWZhdWx0LXBsYXRmb3JtIn1dLCJvcmdhbml6YXRpb24iOlt7InJvbGVfaWQiOiJlc3MtZGVmYXVsdC1vcmdhbml6YXRpb24iLCJvcmdhbml6YXRpb25faWQiOiIxMjM0NTY3ODkwIn0seyJyb2xlX2lkIjoib3JnYW5pemF0aW9uLWFkbWluIiwib3JnYW5pemF0aW9uX2lkIjoiMTIzNDU2Nzg5MCJ9XSwidXNlciI6W3sicm9sZV9pZCI6ImVzcy1kZWZhdWx0LXVzZXIiLCJzZWN1cml0eV9yZWFsbSI6eyJyZWFsbSI6InBvc3RncmVzIn0sInVzZXJfaWQiOiI5ODc2NTQzMjEifV19LCJpc3MiOiJlbGFzdGljLWNsb3VkIiwidHlwIjoiYWNjZXNzLXRva2VuIiwib2lkIjoiMTIzNDU2Nzg5MCIsImV4cCI6MjA3MDcxMDIxNSwic2p0IjoidXNlciIsImlhdCI6MTc1NTE3MTMwOCwianRpIjoiNDg5YzZjOTRmMzBlNGRiYjkzNDY4ZjhkYTQyOTExYzQiLCJlbWFpbCI6ImFsZmEuYmV0YUBlbGFzdGljLmNvIn0.HIW_dEiNBjaSB1lWwIfpovTxn0o725vnL4b_Y41yagU" \
    -H "X-Client-Authentication: XmLutyDzrWDcz9i+xXRXzSMJEfulI+Q9yIaibncLRyA=" \
    -d '{
          "contexts": [
            {
              "project_id": "abcdef1234567890abcdef1234567890",
              "project_organization_id": "1234567890",
              "project_type": "elasticsearch",
              "type": "project"
            }
          ]
        }'
```