#include <iostream>
#include <cstdint>

#include <unistd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <fcntl.h>
using namespace std;

// http://www.sans.org/reading-room/whitepapers/forensics/reverse-engineering-microsoft-exfat-file-system-33274
struct __attribute__((__packed__)) exfat_vbr
{
  uint8_t jump_boot[3];
  uint8_t file_system_name[8];
  uint8_t zero[53];
  uint64_t partition_offset;
  uint64_t volume_length;
  uint32_t fat_offset;
  uint32_t fat_length;
  uint32_t cluster_heap_offset;
  uint32_t cluster_count;
  uint32_t root_dir_first_cluster;
  uint32_t volume_serial_number;
  struct
  {
    uint8_t minor;
    uint8_t major;
  } file_system_revision;
  struct
  {
    uint16_t active_fat:1;
    uint16_t volume_dirty:1;
    uint16_t media_failure:1;
    uint16_t zero:1;
    uint16_t reserved:12;
  } volume_flags;
  uint8_t bytes_per_sector;
  uint8_t sector_per_cluster;
  uint8_t fats_count;
  uint8_t drive_select;
  uint8_t percent_in_use;
  uint8_t reserved[7];
  uint8_t boot_code[390];
  uint16_t boot_signature;
};

static_assert(sizeof(exfat_vbr) == 512, "exfat_vbr is not packed");

void print_vbr(exfat_vbr& vbr) {
  cout << "jump_boot[3]: 0x" << hex << (vbr.jump_boot[2] | (vbr.jump_boot[1] << 8) | (vbr.jump_boot[0] << 16)) << dec << endl 
    << "file_system_name[8]: " << (char*)vbr.file_system_name << endl 
    << "zero[53]: " << (int)vbr.zero[0] << endl 
    << "partition_offset: " << vbr.partition_offset << endl 
    << "volume_length: " << vbr.volume_length << endl 
    << "fat_offset: " << vbr.fat_offset << endl 
    << "fat_length: " << vbr.fat_length << endl 
    << "cluster_heap_offset: " << vbr.cluster_heap_offset << endl 
    << "cluster_count: " << vbr.cluster_count << endl 
    << "root_dir_first: " << vbr.root_dir_first_cluster << endl 
    << "volume_serial_number: " << vbr.volume_serial_number << endl 
    << "file_system_revision: " << endl
    << "  major: " << (int)vbr.file_system_revision.major << endl
    << "  minor: " << (int)vbr.file_system_revision.minor << endl
    << "volume_flags: " << endl
    << "  active_fat: " << vbr.volume_flags.active_fat << endl
    << "  volume_dirty: " << vbr.volume_flags.volume_dirty << endl
    << "  media_failure: " << vbr.volume_flags.media_failure << endl
    << "  zero: " << vbr.volume_flags.zero << endl
    << "  reserved: " << vbr.volume_flags.reserved << endl
    << "bytes_per_sector: 2^" << (int)vbr.bytes_per_sector << endl 
    << "sector_per_cluster: 2^" << (int)vbr.sector_per_cluster << endl 
    << "fats_count: " << (int)vbr.fats_count << endl 
    << "drive_select: " << (int)vbr.drive_select << endl 
    << "percent_in_use: " << (int)vbr.percent_in_use << endl 
    << "reserved[7]: " << (int)vbr.reserved[0] << endl 
    << "boot_code[390]: " << vbr.boot_code[0] << endl 
    << "boot_signature: 0x" << hex << vbr.boot_signature << dec << endl
    << endl;
}

#define ADDSUM(sum, byte) ((sum << 31) | (sum >> 1)) + byte
bool verify_vbr(exfat_vbr& vbr, int fd)
{
  size_t sector_size = 1 << vbr.bytes_per_sector;
  uint8_t* sector_buffer = new uint8_t[sector_size];

  uint32_t checksum = 0;
  for (int sector = 0; sector < 11; sector++)
  {
    pread(fd, sector_buffer, sector_size, sector * sector_size);
    for (int i = 0; i < sector_size; i++)
    {
      if (sector || (i != 0x6a && i != 0x6b && i != 0x70)) {
        // skip volume_flags and percent_in_use in vbr*/
        checksum = ADDSUM(checksum, sector_buffer[i]);
      }
    }
  }
  
  pread(fd, sector_buffer, sector_size, 11 * sector_size);
  for (int i = 0; i < sector_size / sizeof(uint32_t); i++)
  {
    if (((uint32_t*)sector_buffer)[i] != checksum)
    {
      cerr << "invalid checksum 0x" << hex << checksum << " (expected 0x" << ((uint32_t*)sector_buffer)[i] << ")" << endl;
      return false;
    }
  }
  return true;
}

void usage()
{
  cerr << "USAGE: exfat_clean [-yvh] rdisk" << endl
    << endl
    << "OPTIONS: " << endl
    << "  -y     Assume yes" << endl
    << "  -v     Version" << endl
    << "  -h     Help" << endl
    << "  rdisk  Raw exfat disk" << endl
    << endl;
  cerr << "exfat_clean v1.0.0" << endl
    << "SOURCE: https://github.com/zzh8829/exfat_clean" << endl
    << "LICENSE: MIT 2017 Zihao Zhang" << endl;
}

int main(int argc, char* argv[])
{
  int ch;
  int yes = 0;

  while ((ch = getopt(argc, argv, "yh")) != EOF)
  {
    switch (ch)
    {
    case 'y':
      yes++;
    case 'h':
    default:
      usage();
      return 0;
      break;
    }
  }

  argc -= optind;
  argv += optind;

  if (argc != 1) {
    cerr << "ERROR: rdisk missing!" << endl;
    usage();
    return 1;
  }

  int fd = open(argv[0], O_RDWR);

  exfat_vbr vbr;

  if (pread(fd, &vbr, sizeof(vbr), 0) < 0) {
    cerr << "vbr read failed" << endl;
    return 1;
  }

  print_vbr(vbr);

  if(!verify_vbr(vbr, fd)) {
    cerr << "checksum failed" << endl;
    return 1;
  } else {
    cout << "checksum ok" << endl;
  }

  if(!vbr.volume_flags.volume_dirty) {
    cout << "exfat is already clean" << endl;
    return 0;
  } else {
    cout << "exfat is dirty" << endl;
  }

  if(!yes) {
    string ans;
    cout << "are you sure about flipping dirty bit" << endl
      << "NOT RESPONSIBLE FOR DATA LOSE!!! [y/n]" << endl;
    cin >> ans;
    if(ans != "y" && ans != "Y") {
      cout << "nothing happened" << endl;
      close(fd);
      return 0;
    }      
  }

  cout << "flipping dirty bit" << endl;
  vbr.volume_flags.volume_dirty = 0;

  if(pwrite(fd, &vbr, sizeof(vbr), 0) < 0) {
    cerr << "write failed" << endl;
    return 1;
  }

  if(fsync(fd)) {
    cerr << "fsync failed" << endl;
    return 1;
  }

  cout << "all good" << endl;
  
  close(fd);
  return 0;
}
