# Language Security Reference (Extended)

Extended security quirks for languages covered briefly or not listed in `owasp-web` skill.
Reference this file when doing deep security reviews in these specific languages.

---

## Swift
**Main Risks:** Force unwrapping crashes, Objective-C interop, insecure storage
```swift
// UNSAFE: force unwrap on untrusted data
let value = jsonDict["key"]!
// SAFE: guard unwrap
guard let value = jsonDict["key"] else { return }

// UNSAFE: format string with user input
String(format: userInput, args)
// SAFE: never use user input as format string
```
**Watch for:** `!` force unwrap, `try!`, ObjC bridging, `NSSecureCoding` misuse, `UserDefaults` for secrets

---

## Kotlin
**Main Risks:** Null safety bypass, Java interop, serialization, reflection
```kotlin
// UNSAFE: platform type from Java (can NPE)
val len = javaString.length
// SAFE: explicit null handling
val len = javaString?.length ?: 0

// UNSAFE: reflection with user input
clazz.getDeclaredMethod(userInput)
// SAFE: allowlist method names
val allowed = mapOf("greet" to Greeter::greet)
allowed[userInput]?.call(instance)
```
**Watch for:** Java interop `!!` operator, `@Serializable` with dynamic types, `Class.forName(userInput)`

---

## Scala
**Main Risks:** XML XXE, Java interop, pattern match exhaustiveness, serialization
```scala
// UNSAFE: XXE in XML parsing
val xml = XML.loadString(userInput)

// SAFE: disable external entities
val factory = javax.xml.parsers.SAXParserFactory.newInstance()
factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
```
**Watch for:** `Serializable` trait, `scala.reflect` usage, non-exhaustive pattern matches, Java lib interop

---

## R
**Main Risks:** Code injection via eval, file path manipulation, package supply chain
```r
# UNSAFE: eval injection
eval(parse(text = user_input))
# SAFE: never parse user input as code

# UNSAFE: path traversal
read.csv(paste0("data/", user_file))
# SAFE: validate filename strictly
if (!grepl("^[a-zA-Z0-9_-]+\\.csv$", user_file)) stop("Invalid filename")
read.csv(file.path("data", user_file))
```
**Watch for:** `eval()`, `parse()`, `source()`, `system()`, `system2()`, file path construction from user input

---

## Perl
**Main Risks:** Two-arg open injection, regex DoS, taint mode bypass, eval
```perl
# UNSAFE: two-arg open — command injection if $file starts with |
open(FILE, $user_file);

# SAFE: three-arg open
open(my $fh, '<', $user_file) or die "Cannot open: $!";

# UNSAFE: ReDoS
$input =~ /$user_pattern/;
# SAFE: use quotemeta
$input =~ /\Q$user_pattern\E/;
```
**Watch for:** Two-arg `open()`, backticks, `eval`, regex from user input, disabled taint mode (`-T`)

---

## Lua
**Main Risks:** Sandbox escape via loadstring, os.execute injection, debug library
```lua
-- UNSAFE: code injection
loadstring(user_code)()
loadfile(user_path)()

-- SAFE: restricted sandbox
local env = { math = math, string = string }  -- no os, io, debug
local f = load(user_code, "user", "t", env)
if f then pcall(f) end
```
**Watch for:** `loadstring`, `loadfile`, `dofile`, `os.execute`, `io.popen`, `debug` library access

---

## Elixir
**Main Risks:** Atom exhaustion DoS, code injection, unsafe binary_to_term
```elixir
# UNSAFE: atom exhaustion — atoms are never GC'd
String.to_atom(user_input)
# SAFE: only convert to existing atoms
String.to_existing_atom(user_input)

# UNSAFE: code injection
Code.eval_string(user_input)

# UNSAFE: arbitrary term deserialization (like pickle)
:erlang.binary_to_term(user_binary)
# SAFE: safe flag restricts to primitive types
:erlang.binary_to_term(user_binary, [:safe])
```
**Watch for:** `String.to_atom`, `Code.eval_string`, `:erlang.binary_to_term` without `:safe`, ETS public tables

---

## Dart / Flutter
**Main Risks:** Insecure local storage, platform channel injection, dart:mirrors
```dart
// UNSAFE: storing sensitive data in SharedPreferences
final prefs = await SharedPreferences.getInstance();
prefs.setString('auth_token', token);  // plaintext on disk

// SAFE: flutter_secure_storage uses Keychain/Keystore
const storage = FlutterSecureStorage();
await storage.write(key: 'auth_token', value: token);

// UNSAFE: dynamic method invocation
Function.apply(functions[userInput]!, []);
// SAFE: allowlist function names
const allowed = {'greet': greet, 'help': help};
allowed[userInput]?.call();
```
**Watch for:** `dart:mirrors`, `Function.apply` with user input, `SharedPreferences` for secrets, unvalidated platform channel data

---

## PowerShell
**Main Risks:** Invoke-Expression injection, execution policy bypass, unvalidated paths
```powershell
# UNSAFE: command injection
Invoke-Expression $userInput
& $userVar  # dynamic invocation

# UNSAFE: unvalidated path traversal
Get-Content $userPath

# SAFE: validate path is within allowed directory
$resolvedPath = Resolve-Path $userPath
$allowedBase = "C:\App\Data"
if (-not $resolvedPath.Path.StartsWith($allowedBase)) {
    throw "Path traversal attempt detected"
}
Get-Content $resolvedPath
```
**Watch for:** `Invoke-Expression`, `& $var`, `Start-Process` with user args, `-ExecutionPolicy Bypass`, `[System.Reflection.Assembly]::Load`

---

## Go (Extended)
**Main Risks:** Path traversal, template injection, goroutine leaks, integer overflow
```go
// UNSAFE: path traversal
filePath := filepath.Join("./uploads", userFilename)
// SAFE: verify cleaned path stays within base dir
base := filepath.Clean("./uploads")
full := filepath.Clean(filepath.Join(base, userFilename))
if !strings.HasPrefix(full, base+string(os.PathSeparator)) {
    return errors.New("invalid path")
}

// UNSAFE: template injection — html/template vs text/template
// Always use html/template for user-facing output, never text/template
import "html/template"  // auto-escapes HTML
// NOT: import "text/template"
```
**Watch for:** `text/template` (no escaping) vs `html/template`, `unsafe.Pointer`, goroutine leaks, `math/rand` vs `crypto/rand`

---

## Java (Extended)
**Main Risks:** JNDI injection (Log4Shell pattern), XXE, deserialization, expression injection
```java
// UNSAFE: expression language injection (e.g., in JSP/JSF, Spring SpEL)
ExpressionParser parser = new SpelExpressionParser();
parser.parseExpression(userInput).getValue();  // RCE

// SAFE: allowlist expressions or use literal values
// Never evaluate user input as SpEL expression

// UNSAFE: JNDI lookup with user input (Log4Shell pattern)
context.lookup("ldap://" + userInput);
// SAFE: validate JNDI URLs against strict allowlist; disable remote class loading
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "false");
```
**Watch for:** SpEL injection in Spring, JNDI lookups, `Runtime.getRuntime().exec()`, `ProcessBuilder` with user input, `Class.forName(userInput)`

---

## C# (Extended)
**Main Risks:** Path traversal, LDAP injection, XML injection, regex DoS
```csharp
// UNSAFE: path traversal
var path = Path.Combine("uploads", userInput);
// SAFE: verify path stays within base
var basePath = Path.GetFullPath("uploads");
var fullPath = Path.GetFullPath(Path.Combine("uploads", userInput));
if (!fullPath.StartsWith(basePath + Path.DirectorySeparatorChar))
    throw new UnauthorizedAccessException();

// UNSAFE: ReDoS — catastrophic backtracking
Regex.IsMatch(input, @"(a+)+b");
// SAFE: set timeout
new Regex(@"(a+)+b", RegexOptions.None, TimeSpan.FromMilliseconds(100)).IsMatch(input);
```
**Watch for:** `BinaryFormatter` (banned in .NET 7+), `TypeNameHandling.All` in Newtonsoft.Json, LDAP injection via `DirectorySearcher`, `Process.Start` with user input

---

## PHP (Extended)
**Main Risks:** Type juggling, deserialization POP chains, file inclusion, SSRF
```php
// UNSAFE: object injection via unserialize
$data = unserialize($_COOKIE['user_data']);  // RCE via POP chain

// SAFE: use JSON
$data = json_decode($_COOKIE['user_data'], true);

// UNSAFE: SSRF via file_get_contents
$content = file_get_contents($_GET['url']);

// SAFE: validate URL and block internal ranges
$url = $_GET['url'];
$host = parse_url($url, PHP_URL_HOST);
if (filter_var($host, FILTER_VALIDATE_IP) &&
    !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    die("Internal URLs not allowed");
}
```
**Watch for:** `unserialize()`, `preg_replace` with `/e` modifier (removed in PHP 7), `extract()`, `$$varVariable`, type juggling with `==`

---

## Rust (Extended)
**Main Risks:** Unsafe blocks, integer overflow in release, FFI, panic in libraries
```rust
// UNSAFE: raw pointer dereference
unsafe { *user_ptr }

// CAUTION: integer overflow wraps silently in release
let x: u8 = 200u8;
let y = x + 100;  // 44 in release, panic in debug

// SAFE: explicit checked arithmetic
let y = x.checked_add(100).ok_or("overflow")?;

// UNSAFE: string from raw bytes without validation
let s = unsafe { String::from_utf8_unchecked(bytes) };
// SAFE
let s = String::from_utf8(bytes).map_err(|_| "invalid utf8")?;
```
**Watch for:** `unsafe` blocks (audit every one), `mem::transmute`, raw pointers, `from_raw`/`into_raw`, `.unwrap()` / `.expect()` on untrusted input, `std::process::Command` with user input

---

## Shell / Bash (Extended)
```bash
# UNSAFE: glob expansion with user input
rm /uploads/$user_file  # if $user_file is "* important_config.txt"
                         # expands to delete everything then important_config.txt

# SAFE: use -- to end options, quote thoroughly
rm -- "/uploads/$user_file"

# UNSAFE: word splitting
for f in $files; do ...  # splits on whitespace
# SAFE
while IFS= read -r f; do ...; done <<< "$files"

# Always start scripts with:
set -euo pipefail  # -e exit on error, -u unbound vars, -o pipefail
```
**Watch for:** unquoted variables, `eval`, `source` with user input, `IFS` manipulation, missing `set -euo pipefail`, world-writable temp files

---

## SQL (Extended)
```sql
-- UNSAFE: dynamic SQL in stored procedures
EXEC('SELECT * FROM ' + @tableName)  -- SQL Server
EXECUTE IMMEDIATE 'SELECT * FROM ' || tableName;  -- Oracle

-- SAFE: allowlist table/column names, never concatenate
IF @tableName NOT IN ('orders', 'products', 'users')
    RAISERROR('Invalid table', 16, 1);
SELECT * FROM orders;  -- use static query after validation

-- UNSAFE: privilege escalation via definer
CREATE PROCEDURE as_admin()
DEFINER = 'root'@'%'  -- runs with root privileges
SQL SECURITY DEFINER  -- dangerous if procedure is injectable
```
**Watch for:** `EXECUTE IMMEDIATE`, dynamic column/table names, `SQL SECURITY DEFINER` stored procedures, `xp_cmdshell` (SQL Server), `UTL_FILE`/`UTL_HTTP` (Oracle)
