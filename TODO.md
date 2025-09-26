# TODO

## tools

### strace

- [x] basics  
- [x] update README.md  
- [x] handle signals  
- [ ] add missing syscalls in syscall/info.json  
- [ ] follow child on fork  
- [ ] syscall filtering  

### sscov

- [x] basics  
- [x] update README.md  
- [x] support PIE  

### addr2line

- [x] basics  
- [x] update README.md  
- [x] support PIE  
- [ ] support DWARF5  

### gcov

- [x] basics  
- [x] update README.md  
- [ ] ~~skip basic blocks (optimization)~~

### dbg

- [x] basics  
- [x] update README.md  
- [x] testing  
- [ ] allow breakpoints on lines/functions  
- [ ] make `list` display more than just the current line  
- [ ] add function params to `backtrace`  
- [ ] `print`/`display` variables content  

### ltrace

- [ ] basics  
- [ ] update README.md  

### mmck

- [ ] basics  
- [ ] update README.md  

### ld

- [ ] basics  
- [ ] update README.md  

### ld.so

- [ ] basics  
- [ ] update README.md  

## infra

- [x] apply clippy::pedantic lints  
- [x] testing  
  - [x] unit tests  
  - [x] integration tests  
- [x] documentation  
  - [x] basics  
  - [x] pub structs  
- [ ] support more architectures  
- [ ] fix build warnings
