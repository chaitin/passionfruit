#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

/*
    ignore these error:

    'libkern/machine/OSByteOrder.h' file not found
    #include <libkern/machine/OSByteOrder.h>

    printf is for debugging, use DYLD_INSERT_LIBRARIES to load me
*/

extern "C" void checksec(char *buf, size_t *size) {
  NSMutableArray *flags = [NSMutableArray array];
  void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
  struct mach_header *mh =
      (struct mach_header *)dlsym(handle, "_mh_execute_header");
  struct load_command *lc;

  if (mh->magic == MH_MAGIC_64) {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header_64));
  } else {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header));
  }

  if (mh->flags & MH_PIE) {
    printf("[+] PIE\n");
    [flags addObject:@"PIE"];
  }

  if (mh->flags & MH_ALLOW_STACK_EXECUTION) {
    printf("[+] ALLOW_STACK_EXECUTION\n");
    [flags addObject:@"ALLOW_STACK_EXECUTION"];
  }

  if (mh->flags & MH_NO_HEAP_EXECUTION) {
    printf("[+] NO_HEAP_EXECUTION\n");
    [flags addObject:@"NO_HEAP_EXECUTION"];
  }

  for (int i = 0; i < mh->ncmds; i++) {
    if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
      struct encryption_info_command *eic =
          (struct encryption_info_command *)lc;
      if (eic->cryptid == 1) {
        printf("[+] encrypted\n");
        [flags addObject:@"ENCRYPTED"];
      }
    } else if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64) {
      struct segment_command *sc = (struct segment_command *)lc;
      if (strcmp(sc->segname, "__RESTRICTED") &&
          strcmp(sc->segname, "__restricted")) {
        printf("[+] segment: %s\n", sc->segname);
      } else {
        printf("[+] restricted\n");
        [flags addObject:@"RESTRICTED"];
      }
    }
    lc = (struct load_command *)((unsigned char *)lc + lc->cmdsize);
  }

  NSString *joint = [flags componentsJoinedByString:@","];
  *size = [joint length];
  strncpy(buf, [joint UTF8String], *size);
  printf("%s\n%lu\n", buf, *size);
}

/* debug */
__attribute__((constructor)) void entrance(int argc, const char **argv,
                                             const char **envp,
                                             const char **apple,
                                             struct ProgramVars *pvars) {
  char buf[1024];
  size_t size = strlen(buf);
  checksec(buf, &size);
}
// vim:ft=objc