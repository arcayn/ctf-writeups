# The Vault

**Writeup by: ** arcayn
**Category: ** Rev
**Difficulty: ** Medium

We are given a binary file. Opening it up in Ghidra, we head to the main function. Following a couple of function pointers through, we arrive at:
```C
void FUN_0010c220(void)

{
  byte bVar1;
  long in_FS_OFFSET;
  byte local_241;
  uint counter;
  char local_219;
  long local_218 [65];
  long local_10;
  bool flag_accepted;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  _ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode(local_218,"flag.txt",8);
                    /* try { // try from 0010c25e to 0010c400 has its CatchHandler @ 0010c2a5 */
  bVar1 = _ZNSt14basic_ifstreamIcSt11char_traitsIcEE7is_openEv(local_218);
  if ((bVar1 & 1) == 0) {
    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
              (&std::cout,"Could not find credentials\n");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  flag_accepted = true;
  counter = 0;
  while( true ) {
    local_241 = 0;
    if (counter < 0x19) {
      local_241 = _ZNKSt9basic_iosIcSt11char_traitsIcEE4goodEv
                            ((long)local_218 + *(long *)(local_218[0] + -0x18));
    }
    if ((local_241 & 1) == 0) break;
    _ZNSi3getERc(local_218,&local_219);
    bVar1 = (***(code ***)(&PTR_PTR_00117880)[(byte)(&DAT_0010e090)[(int)counter]])();
    if ((int)local_219 != (uint)bVar1) {
      flag_accepted = false;
    }
    counter = counter + 1;
  }
  if (flag_accepted) {
    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
              (&std::cout,"Credentials Accepted! Vault Unlocking...\n");
  }
  else {
    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
              (&std::cout,"Incorrect Credentials - Anti Intruder Sequence Activated...\n");
  }
  _ZNSt14basic_ifstreamIcSt11char_traitsIcEED1Ev(local_218);
  if (*(long *)(in_FS_OFFSET + 0x28) == local_10) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
From this, we can see that we have to create a file called `flag.txt`, whose contents passes some checks - and then the vault will open. Let's examine these checks in more detail. The main verification loop is within `while (true)`, and it follows a sequence of steps. First, the next character in the file is loaded into `local_219`:
```C
    local_241 = 0;
    if (counter < 0x19) {
      local_241 = _ZNKSt9basic_iosIcSt11char_traitsIcEE4goodEv
                            ((long)local_218 + *(long *)(local_218[0] + -0x18));
    }
    if ((local_241 & 1) == 0) break;
    _ZNSi3getERc(local_218,&local_219);
```
Furthermore, if the counter exceeds `0x19 = 25` at this point, then the verification process is over. We can trick this, but we want to engineer a flag which passes this check. Now a check is performed on this character, and `flag_accepted` is set to false if it fails.
```C
bVar1 = (***(code ***)(&PTR_PTR_00117880)[(byte)(&DAT_0010e090)[(int)counter]])();
if ((int)local_219 != (uint)bVar1) {
  flag_accepted = false;
}
```
The whole flag is thus iterated over, character by character, and this check is performed on each one. If the check passes for all of them, then the vault unlocks.

We use ANGR. Clearly our conditions are going to be to always avoid the `flag_accepted = false;` branch, and to find a path which leads to the 
```
_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
              (&std::cout,"Credentials Accepted! Vault Unlocking...\n");
```
branch. We extract the address of the branch to avoid as `0xc3a9`, and for the branch to find:  `0xc3df`. ANGR loads the binary with an address offset of `0x400000`, so we remember to include this. Using ANGR `explore` will be incredibly fast, since the single branch to avoid means that we can easily check the flag character-by-character with only 25 branches. The solve script is below, and it takes approximately 10 seconds to run:
```python
import angr
import claripy

p = angr.Project('vault')

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(0x19)]
flag = claripy.Concat(*flag_chars)
    
filename = 'flag.txt'
simfile = angr.SimFile(filename, content=flag)

state = p.factory.full_init_state(
        fs={filename: simfile},
        add_options=angr.options.unicorn)

for k in flag_chars:
        state.solver.add(k < 0x80)
        state.solver.add(k > 0x20)
 
sm = p.factory.simulation_manager(state)

ANGR_BASE = 0x400000
avadd = 0xc3a9 + ANGR_BASE
fadd = 0xc3df + ANGR_BASE

print ("Simulating...")  
sm.explore(avoid = [avadd], find=[fadd])
for aa in sm.found:
    print (aa.solver.eval(flag,cast_to=bytes))
```
And we get the flag as:

`HTB{vt4bl3s_4r3_c00l_huh}`