#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <iterator>
#include <set>
#include <sstream>
#include <string>

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

__attribute__((visibility("default"))) extern "C" void checksec(char *buf,
                                                                size_t *size) {
  struct mach_header *mh = (struct mach_header *)_dyld_get_image_header(0);
  struct load_command *lc;
  std::set<std::string> flags;

  if (!mh) {
    // todo: return status code
    NSLog(@"unable to read macho header");
    strncpy(buf, "ERROR: unable to read macho header", *size);
    return;
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
    flags.insert("PIE");
  }

  if (mh->flags & MH_ALLOW_STACK_EXECUTION) {
    NSLog(@"[+] ALLOW_STACK_EXECUTION\n");
    flags.insert("ALLOW_STACK_EXECUTION");
  }

  if (mh->flags & MH_NO_HEAP_EXECUTION) {
    NSLog(@"[+] NO_HEAP_EXECUTION\n");
    flags.insert("NO_HEAP_EXECUTION");
  }

  for (int i = 0; i < mh->ncmds; i++) {
    switch (lc->cmd) {
    case LC_ENCRYPT_INFO: {
      struct encryption_info_command *eic =
          (struct encryption_info_command *)lc;
      if (eic->cryptid == 1) {
        NSLog(@"[+] encrypted\n");
        flags.insert("ENCRYPTED");
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
        flags.insert("RESTRICTED");
      } else {
        NSLog(@"[+] segment: %s\n", seg->segname);
      }
      break;
    }
    }
    lc = (struct load_command *)((unsigned char *)lc + lc->cmdsize);
  }

  std::ostringstream joint;
  std::copy(flags.begin(), flags.end(),
            std::ostream_iterator<std::string>(joint, ","));
  std::string str = joint.str();
  strncpy(buf, str.c_str(), *size);
  *size = str.length();
  NSLog(@"%s\n%lu\n", buf, *size);
}

// vim:ft=objc