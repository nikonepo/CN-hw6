# CN-hw6

## Simple implementation nfqueue firewall for http packets

Build:

```go build```

Run:

```./hw6```

## Rules

Rules are stored in `rules.json` file.

- This example file contains 2 rules, that delete HTTP packets with conditions:
```json
[
  {
    "Type": "delete",
    "Host": "google.com",
    "Method": "GET",
    "UserAgent": "curl",
    "PathPrefix": "/api",
    "ContentLen": 1024
  },
  {
    "Type": "delete",
    "Host": "",
    "Method": "PUT",
    "UserAgent": "",
    "PathPrefix": "",
    "ContentLen": 0
  }
]
```

There are 2 types of rules:
- `delete` - delete packets that match the rule
- `skip` - skip packets that match the rule