## TypedConverter
### General architecture
![dependencies.drawio.png](dependencies.drawio.png)

### Message converters
(Almost) Each message type is handled by a respective handler returns a string representation of the converted message.  
The handlers must not change the converted value(e.g. adding prefix shifts, etc...). If such adjustments are required, it should be managed by a caller of the handler.

### Implemented statements
* Build-in calls
* For-loop statements
* If-statements
* Typed expressions  
_The result of a typed expression can be assigned to a variable and passed to a statement accepting a value or an expression of the respective type  
Also, an expression can be combined from other expressions_
  * Build-ins
  * Var references
  * Binary operation
  * Unary operation
