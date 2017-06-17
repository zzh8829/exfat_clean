## Clean Dirty ExFAT Partition

macOS has a very dumb ExFAT driver compare to the one on Windows. The mac driver currupts ExFAT formatted portatable drive very often and take forever to repair. Bootcamp into Windows was my only option to clean currpted ExFAT hard drive. Now with exfat_clean you can solve this in under 1 second :)

## WARNING
This may result in data loss, only use it if you are 100% sure the driver is being dumb and the hard drive is not actually corrupted.

## How to use
1. Find out your hard drive's ID

```
$ diskutil list
... (skipped)
/dev/disk2 (external, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:     FDisk_partition_scheme                        *1.0 TB     disk2
   1:               Windows_NTFS Portable Drive          1.0 TB     disk2s1
```

2. Now fix it
```
$ ./exfat_clean /dev/rdisk2s1
```
Note we are using the raw disk id for the partition **r**disk2s1


## How does this work
Long story short in the ExFAT partition header there is a bit called dirty bit. This program changes dirty bit to clean so the system assume the drive is already repaired (it was never broken to began with)
