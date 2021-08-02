# Drogon Assist

Drogon Assist is a 3rd party toolkit (even though the author is a maintainer of Drogon) for features that doesn't make it into Drogon's repository. Either because it is out of scope for the core frameowrk, too much dependency or just because.

Dependencies:
 * libbsd (if not on *BSD)
 * Botan-2

**Note:** You need to recompile this library after any update to Drogon. Otherwise ABI incompatablity may cause unexpected issues.

## Features:

### Easy Password Hashing

```c++
#include <drogon/assist/passwdhash.hpp>

std::string hashed = drassist::passwdhash::hash("12456");
// ARGON2:QrrB8NQCF5JlfWoA:$argon2id$v=19$m=65536,t=2,p=1$+HCM3JuBVPkeF3QiGo7PdA$zIOLPhwKVdSCUfMtq1zd+rCJ9DSMVhkSV+43TRUGtLw

drassist::passwdhash::verify("123456", hashed); // true
drassist::passwdhash::verify("abcdef", hashed); // false
```

### Useful Plugins

 * Stop HTTP parameter pollution

```json
/*Add this into Drogon's configuration file*/
{
	"name": "drassist::ParameterPollutionProtector",
}
```

* Remove BOM from common content types
```json
/*Add this into Drogon's configuration file*/
{
	"name": "drassist::BOMRemover",
}
```


And more..
