# Serialization & Deserialization Vulnerability Research

## Overview

People often find serialization/deserialization vulnerabilities by treating the deserializer as both:

1. An **input parser**
2. An **object-construction mechanism**

The central security question is:

> **What can an attacker make the application reconstruct that the developer never intended?**

---

## 1. Map the Data Flow

First identify where serialized data enters the application.

Common entry points include:

* HTTP request bodies
* Cookies
* Tokens
* Message queues
* Uploaded files
* Cache entries
* RPC calls
* Database fields
* Inter-service communication

Then trace the data through the application:

```text
Attacker-controlled input
        ↓
Decoding
        ↓
Parsing
        ↓
Deserialization
        ↓
Object construction
        ↓
Application logic
        ↓
Sensitive operation
```

Important question:

> Is the serialized data actually trusted, or can an attacker influence it?

---

## 2. Understand the Serialization Format

Different serialization formats have different security characteristics.

Examples:

* JSON
* XML
* YAML
* Protocol Buffers
* Java serialization
* Python `pickle`
* .NET serializers
* PHP serialization
* Custom binary formats

Look for advanced features such as:

* Polymorphic types
* Type metadata
* Object references
* Recursive references
* Aliases
* Custom constructors
* Custom converters
* Lifecycle callbacks
* Embedded class/type information

The more powerful the serialization format is, the more carefully its deserialization behavior should be examined.

---

## 3. Look for Dangerous Type Handling

A major red flag is allowing serialized input to determine what type/class gets instantiated.

Conceptually, this is dangerous:

```text
deserialize(input, type_supplied_by_input)
```

Compared with the safer model:

```text
deserialize(input, ExpectedDTO)
```

Attacker-controlled type information can sometimes result in unexpected classes or objects being instantiated.

Questions to ask:

* Can the input specify a class?
* Can it select a subtype?
* Can it modify type metadata?
* Is polymorphic deserialization enabled?
* Is there a whitelist of allowed types?
* Does the application assume the resulting object is a particular class?

---

## 4. Fuzz Malformed Inputs

Researchers frequently use fuzzing to discover unexpected parser or deserializer behavior.

Useful areas to vary include:

### Structure

* Missing fields
* Extra fields
* Duplicate fields
* Unexpected nesting
* Recursive structures
* Empty structures

### Types

Try changing expected types:

```text
string → integer
integer → string
array → object
object → array
boolean → string
null → object
```

### Boundaries

Test:

* Zero
* Negative values
* Very large values
* Empty strings
* Extremely long strings
* Very large arrays
* Deeply nested objects

### Encoding

Depending on the format, investigate:

* Invalid encodings
* Unicode edge cases
* Escaping
* Duplicate representations
* Malformed lengths
* Unexpected byte sequences

Observe whether the application:

* Crashes
* Hangs
* Consumes excessive CPU
* Consumes excessive memory
* Produces unexpected objects
* Bypasses validation
* Behaves differently between components

---

## 5. Compare Serialization and Deserialization

Another useful technique is examining whether serialization and deserialization preserve security-relevant properties.

Conceptually:

```text
serialize(deserialize(input))
```

should produce something semantically consistent with the original data.

Interesting discrepancies include:

* Fields disappearing
* Fields being added
* Values changing type
* Defaults being inserted
* Validation being skipped
* Case differences being normalized
* Duplicate fields being handled differently
* Internal fields becoming exposed
* Trusted fields being reconstructed from untrusted data

These differences can sometimes produce security issues.

---

## 6. Inspect Custom Deserialization Hooks

Custom deserialization code deserves particular attention.

Depending on the language/framework, examples can include:

* `readObject`
* `writeObject`
* `__setstate__`
* Custom constructors
* Custom converters
* Type resolvers
* Deserialization callbacks
* Object lifecycle hooks

The important question is:

> Does "parsing data" cause application code to execute or perform sensitive operations?

A deserializer that merely constructs a data-transfer object is generally less interesting than one that invokes substantial application behavior during reconstruction.

---

## 7. Test Authorization Assumptions

Not every deserialization vulnerability leads to code execution.

A very common class of issue is **trusting security-sensitive fields supplied through serialized data**.

For example:

```json
{
  "userId": 123,
  "role": "admin"
}
```

Suppose the application deserializes this directly into an internal object and subsequently trusts:

```text
object.role
```

An attacker may be able to manipulate application state or authorization decisions.

Look for fields such as:

* User IDs
* Account IDs
* Roles
* Permissions
* Ownership
* IsAdmin
* IsVerified
* Pricing
* Account status
* Internal flags

The key question is:

> Which fields should be determined by the server rather than by the serialized input?

---

## 8. Look for Resource-Exhaustion Problems

Deserialization can sometimes transform a relatively small input into a very large or expensive object structure.

Investigate:

### Deep nesting

```text
object
 └── object
      └── object
           └── object
                └── ...
```

### Huge collections

```text
[
  item,
  item,
  item,
  ...
]
```

### Recursive references

Objects that refer back to themselves or create very large object graphs.

### Expensive structures

Some formats or implementations can trigger expensive operations during parsing or reconstruction.

Potential symptoms:

* Excessive CPU consumption
* Excessive memory consumption
* Long processing times
* Stack exhaustion
* Application crashes
* Worker/thread exhaustion

This can lead to denial-of-service vulnerabilities.

---

# A Practical Audit Methodology

When auditing a deserialization process, walk through the following chain:

```text
1. Can I control the serialized bytes?
                ↓
2. Can I control the structure?
                ↓
3. Can I control the type?
                ↓
4. Can I control the resulting object's fields?
                ↓
5. Does object creation invoke application code?
                ↓
6. Does the application trust the resulting object?
                ↓
7. Can the input consume excessive resources?
```

Each "yes" identifies an area worth investigating.

---

# Vulnerability Categories

## 1. Unsafe Object Construction

Untrusted data causes unexpected objects/classes to be instantiated.

Potential consequences depend heavily on the framework and application.

---

## 2. Type Confusion

The application expects one type but allows input to influence another type being created or interpreted.

Example concept:

```text
Expected:
UserDTO

Attacker-controlled:
SomeOtherType
```

---

## 3. Privilege Escalation

Security-sensitive properties are populated from attacker-controlled serialized data.

Example:

```json
{
  "userId": 123,
  "isAdmin": true
}
```

---

## 4. Validation Bypass

The serialized representation and the application's internal representation don't enforce the same validation rules.

For example:

```text
Input validation
      ↓
Deserializer changes representation
      ↓
Application receives unexpected value
```

---

## 5. Parser Differentials

Different components interpret the same serialized data differently.

For example:

```text
Proxy → interprets data one way
Application → interprets data another way
```

This can become particularly interesting when security checks occur in one component and deserialization occurs in another.

---

## 6. Resource Exhaustion

Malformed or specially structured serialized data causes excessive:

* CPU usage
* Memory usage
* Recursion
* Object creation
* Processing time

---

# Questions to Ask During a Security Review

### Input

* Where does serialized data originate?
* Can an attacker modify it?
* Is integrity/authenticity verified?
* Is it encrypted, signed, or merely encoded?

### Format

* What serialization format is being used?
* Does it support polymorphism?
* Does it support object references?
* Does it support arbitrary types?
* Does it execute callbacks?

### Types

* Who determines the object type?
* Is type metadata attacker-controlled?
* Are allowed types explicitly restricted?
* Is there a type whitelist?

### Fields

* Which fields can the attacker control?
* Are any of those security-sensitive?
* Are internal fields exposed?
* Are defaults automatically applied?

### Execution

* Does deserialization invoke constructors?
* Are custom callbacks executed?
* Are converters involved?
* Does object creation perform I/O or other sensitive operations?

### Availability

* Can a small input create a huge object?
* Is nesting depth limited?
* Are collection sizes limited?
* Is there a timeout?
* Are memory/CPU limits enforced?

### Trust Boundaries

* Does a proxy parse the data differently from the backend?
* Does one service trust objects created by another?
* Is serialized data reused between services?
* Are signed objects actually validated before deserialization?

---

# Defensive Principles

The same observations can be used to design safer systems.

## Prefer Simple Data Structures

Prefer deserializing into narrowly defined DTOs/data structures rather than arbitrary application classes.

```text
Untrusted input
      ↓
Schema validation
      ↓
Restricted DTO
      ↓
Explicit application logic
```

---

## Avoid Arbitrary Type Resolution

Avoid allowing untrusted input to select arbitrary classes.

Prefer:

```text
Input → ExpectedDTO
```

over:

```text
Input → ArbitraryClass
```

---

## Validate Security-Sensitive Fields Server-Side

Do not rely on serialized client data for properties such as:

```text
isAdmin
isVerified
accountOwner
permissions
internalStatus
```

These should generally be derived from trusted server-side state.

---

## Apply Resource Limits

Consider limits for:

* Maximum input size
* Maximum nesting depth
* Maximum collection size
* Maximum processing time
* Maximum memory consumption

---

# Core Mental Model

A useful way to think about serialization security is:

> **Serialization converts application state into data. Deserialization converts data back into application state.**

The security boundary exists at the point where **untrusted data becomes trusted application state**.

Therefore, the most important questions are:

```text
Who controls the data?

        ↓

What can the data control?

        ↓

What object does it become?

        ↓

What happens when that object is created?

        ↓

What does the application trust about it?
```

Understanding that chain makes it much easier to identify both obvious and subtle serialization/deserialization vulnerabilities.
