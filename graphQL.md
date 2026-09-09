## Key Requirements:
- InQL plugin from BApp Store.
- Utilise the introspection query from the default GraphQL reader.

## Things to keep in mind
- The introspection functionality maybe blocked by the developer.
- try inserting a special character after the __schema keyword. When developers disable introspection, they could use a regex to exclude the __schema keyword in queries.
- You should try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.
