#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#if __LP64__
#define LC_ENCRYPT_INFO LC_ENCRYPTION_INFO_64
#define macho_encryption_info_command encryption_info_command_64

#define LC_SEGMENT_COMMAND LC_SEGMENT_64
#define macho_segment_command segment_command_64
#define macho_section section_64

#else
#define LC_ENCRYPT_INFO LC_ENCRYPTION_INFO
#define macho_encryption_info_command encryption_info_command

#define LC_SEGMENT_COMMAND LC_SEGMENT
#define macho_segment_command segment_command
#define macho_section section
#endif

#define FLAG_ENCRYPTED 0x1
#define FLAG_PIE 0x2
#define FLAG_CANARY 0x4
#define FLAG_ARC 0x8
#define FLAG_RESTRICT 0x10

__attribute__((visibility("default"))) extern "C" int8_t ipaspect_checksec() {
  int result = 0;
  struct mach_header *mh = (struct mach_header *)_dyld_get_image_header(0);
  struct load_command *lc;

  if (!mh) {
    NSLog(@"unable to read macho header");
    return -1;
  }

  NSLog(@"checksec on %s", _dyld_get_image_name(0));

  if (mh->magic == MH_MAGIC_64) {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header_64));
  } else {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header));
  }

  if (mh->flags & MH_PIE) {
    NSLog(@"[+] PIE\n");
    result |= FLAG_PIE;
  }

  if (mh->flags & MH_ALLOW_STACK_EXECUTION) {
    NSLog(@"[+] ALLOW_STACK_EXECUTION\n");
  }

  if (mh->flags & MH_NO_HEAP_EXECUTION) {
    NSLog(@"[+] NO_HEAP_EXECUTION\n");
  }

  for (int i = 0; i < mh->ncmds; i++) {
    switch (lc->cmd) {
    case LC_ENCRYPT_INFO: {
      struct encryption_info_command *eic =
          (struct encryption_info_command *)lc;
      if (eic->cryptid != 0) {
        NSLog(@"[+] encrypted\n");
        result |= FLAG_ENCRYPTED;
      }
      break;
    }

    case LC_SEGMENT_COMMAND: {
      const struct macho_segment_command *seg =
          (struct macho_segment_command *)lc;
      bool is_restricted = false;
      if (strcmp(seg->segname, "__RESTRICT") == 0) {
        const struct macho_section *const sections_start =
            (struct macho_section *)((char *)seg +
                                     sizeof(struct macho_segment_command));
        const struct macho_section *const sections_end =
            &sections_start[seg->nsects];
        for (const struct macho_section *sect = sections_start;
             sect < sections_end; ++sect) {
          if (strcmp(sect->sectname, "__restrict") == 0)
            is_restricted = true;
        }
      }
      if (is_restricted) {
        NSLog(@"[+] restricted\n");
        result |= FLAG_RESTRICT;
      } else {
        NSLog(@"[+] segment: %s\n", seg->segname);
      }
      break;
    }
    }
    lc = (struct load_command *)((unsigned char *)lc + lc->cmdsize);
  }

  return result;
}

// vim:ft=objc