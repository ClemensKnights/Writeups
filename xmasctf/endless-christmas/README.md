A classical angr-challenge.

We're presented with an executable that creates a lot of other (temporary) executables and then runs one of them.
This seems to happen in multiple stages, but at some point we will get the one executable that is executed and asks for the flag as input.

You can follow everything with strace and find the last executed file.

I've moved it to `./Execve_With_Flag_Prompt`.

Sounds like a classical angr challenge, so let's go:

```
#!/usr/bin/env python3

import angr
import sys

project = angr.Project('./Execve_With_Flag_Prompt')
initial_state = project.factory.entry_state()
win_addr = 0x400663
simulation.explore(find=win_addr)
print(solution_state.posix.dumps(sys.stdin.fileno()))
```

Yields the solution: X-MAS{d3c0d3_4641n_4nd_4641n_4nd_4641n_4nd_4641n_4nd_fl46}
