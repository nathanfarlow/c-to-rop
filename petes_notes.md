
# C-to-ROP

## Goal: Compile C into a ROP chain


### Step 1 - Turn C into ELVM Assembly

???

### Step 2 - Turn ELVM Assembly into ROP chain

More specifically, for each ELVM opcode, have a tool to translate it to a gagdget. Full OPcode listing [here](https://github.com/shinh/elvm/blob/master/ELVM.md).

For each instruction, we need to turn it into a ROP snippet / chain. Then, we can combine these chains together.

The main issue we face is:

> For any assembly instruction, how can we decompose it into a format that can be solved by angrop / angr?

angrop gives us a list of gadgets that could be useful. They set certain registers, add stuff, etc.

I think the op codes can be split up into a couple categories.

### Category 1: system / libc calls

1) a part of libc
2) involve setting registers (in arm64, for 32-bit the values are just on the stack) then a `call rsp` or smth

Specifics:
```
PUTC
GETC
EXIT
```
### Category 2: Conditionals

Research:

r2 has ROP searches. Needs to be explored. See [here](https://r2wiki.readthedocs.io/en/latest/options/e/values-that-e-can-modify/rop/).

Random resources:
   + https://marcoramilli.com/2011/08/06/rop-conditional-jumps/
   + https://resources.infosecinstitute.com/topic/return-oriented-programming-rop-attacks/
   + https://web.archive.org/web/20120706113115/http://marcoramilli.blogspot.com/2011/08/rop-how-to-make-comparisons.html
+ https://www.cpe.ku.ac.th/~paruj/204554/blackhat08.pdf Slide 24
+ https://course.cs.tau.ac.il/infosec16/sites/drupal-courses.cs.tau.ac.il.infosec16/files/Infosec-R5-ROP.pdf Slide 18

So the idea is to add a certain value to the current stack pointer (ESP) based on the result of some compution. Or, just move this certain value to desired address / memory location.

Specifics:
```
JEQ
JNE
JLT
JGT
JLE
JGE
EQ
NE
LT
GT
LE
GE
```

### Category 3: General computation

This is the meat, should be done first.

Specifics:
```
MOV
ADD
SUB
LOAD ~~ mov dst, QWORD PTR [src]
STORE ~~ mov [dst], src
JMP
```