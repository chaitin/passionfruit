#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <rpc/rpc.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <unistd.h>

#include "libproc.h"
#include "net/route.h"
#include "netinet/tcp_fsm.h"
#include "rpc/pmap_prot.h"
#include "sys/kern_control.h"
#include "sys/proc_info.h"

#import <Foundation/Foundation.h>

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

#define LOG(fmt, ...) NSLog(@"[ipaspect]" fmt, ##__VA_ARGS__)

__attribute__((visibility("default"))) extern "C" int
ipaspect_checkport(char *buf, size_t *size) {
  pid_t pid = getpid();
  LOG("pid: %d", pid);
  int buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
  LOG("buf size: %d", buf_size);
  if (buf_size == -1) {
    LOG("unable to get process fd");
    return -1;
  }

  struct proc_fdinfo *info_array = (struct proc_fdinfo *)malloc(buf_size);
  if (!info_array) {
    LOG("out of memory? must be kidding me.");
    return -1;
  }

  proc_pidinfo(pid, PROC_PIDLISTFDS, 0, info_array, buf_size);
  int n_fd = buf_size / PROC_PIDLISTFD_SIZE;

  @autoreleasepool {
    NSMutableArray *list = [[NSMutableArray alloc] init];
    NSDictionary *dictionary;
    for (int i = 0; i < n_fd; i++) {
      dictionary = nil;
      switch (info_array[i].proc_fdtype) {
      case PROX_FDTYPE_VNODE:

      {
        struct vnode_fdinfowithpath vnodeInfo;
        int byte_used =
            proc_pidfdinfo(pid, info_array[i].proc_fd, PROC_PIDFDVNODEPATHINFO,
                           &vnodeInfo, PROC_PIDFDVNODEPATHINFO_SIZE);
        if (byte_used == PROC_PIDFDVNODEPATHINFO_SIZE) {
          const char *path = vnodeInfo.pvip.vip_path;
          dictionary = [NSDictionary
              dictionaryWithObjectsAndKeys:@"open", @"type",
                                           [NSString stringWithFormat:@"%s", path],
                                           @"path", nil];
          LOG("open file: %s", path);
        }
        break;
      }

      case PROX_FDTYPE_SOCKET:

      {
        struct socket_fdinfo socket_info;
        int byte_used =
            proc_pidfdinfo(pid, info_array[i].proc_fd, PROC_PIDFDSOCKETINFO,
                           &socket_info, PROC_PIDFDSOCKETINFO_SIZE);
        if (byte_used != PROC_PIDFDSOCKETINFO_SIZE)
          continue;
        if (socket_info.psi.soi_family == AF_INET &&
            socket_info.psi.soi_kind == SOCKINFO_TCP) {
          int local_port = (int)ntohs(
              socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
          int remote_port = (int)ntohs(
              socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);

          if (remote_port == 0) {
            dictionary = [NSDictionary
                dictionaryWithObjectsAndKeys:@"listen", @"type",
                                             [NSNumber
                                                 numberWithInt:local_port],
                                             @"local", nil];
            LOG("listening on %d", local_port);
          } else {
            dictionary = [NSDictionary
                dictionaryWithObjectsAndKeys:@"communication", @"type",
                                             [NSNumber
                                                 numberWithInt:local_port],
                                             @"local",
                                             [NSNumber
                                                 numberWithInt:remote_port],
                                             @"remote", nil];
            LOG("connection: %d -> %d", local_port, remote_port);
          }
        }
      }
      }

      if (dictionary) {
        [list addObject:dictionary];
      }
    }
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:list
                                                       options:kNilOptions
                                                         error:&error];
    NSString *jsonString =
        [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSLog(@"%@", jsonString);
    strlcpy(buf, [jsonString UTF8String], *size);
    *size = [jsonString length];
  }
  return 0;
}

__attribute__((visibility("default"))) extern "C" int8_t ipaspect_checksec() {
  int result = 0;
  struct mach_header *mh = (struct mach_header *)_dyld_get_image_header(0);
  struct load_command *lc;

  if (!mh) {
    LOG("unable to read macho header");
    return -1;
  }

  LOG("checksec on %s", _dyld_get_image_name(0));

  if (mh->magic == MH_MAGIC_64) {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header_64));
  } else {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header));
  }

  if (mh->flags & MH_PIE) {
    LOG("[+] PIE\n");
    result |= FLAG_PIE;
  }

  if (mh->flags & MH_ALLOW_STACK_EXECUTION) {
    LOG("[+] ALLOW_STACK_EXECUTION\n");
  }

  if (mh->flags & MH_NO_HEAP_EXECUTION) {
    LOG("[+] NO_HEAP_EXECUTION\n");
  }

  for (int i = 0; i < mh->ncmds; i++) {
    switch (lc->cmd) {
    case LC_ENCRYPT_INFO: {
      struct encryption_info_command *eic =
          (struct encryption_info_command *)lc;
      if (eic->cryptid != 0) {
        LOG("[+] encrypted\n");
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
        LOG("[+] restricted\n");
        result |= FLAG_RESTRICT;
      } else {
        LOG("[+] segment: %s\n", seg->segname);
      }
      break;
    }
    }
    lc = (struct load_command *)((unsigned char *)lc + lc->cmdsize);
  }

  return result;
}

// vim:ft=objc