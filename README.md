# dm-tx
A Linux device mapper module that includes Gecko [USENIX FAST '13], Isotope [USENIX FAST '16], and Yogurt [ACM SoCC '16]. Notice that the code released here is not exactly the same version as the ones used in the papers, but is a reimplementation (some features may be missing or added).

Gecko layer implements the chained-logging design and redirects data blocks into the log. Isotope and Yogurt are built on top of the Gecko layer. Isotope takes care of ACID transactions over the block address space, and Yogurt enables fast but weakly consistent reads. Both Isotope and Yogurt features are accesible through ioctl calls. 

The code has been tested mostly under Linux versions 2.6 and 3.0, or Ubuntu Servers (64-bit) 10.XX and 11.XX. To compile, simply "make" in the src directory. dm-tx is in a form of device-mapper (similar to software RAID and LVM) which creates a logical volume on top of one or many physical block devices. To create a dm-tx volume first review and modify the "in.sh" file in the src directory. Especially, take a careful look at the for loop which determines which physical block devices you want to use under dm-tx. Once in.sh is configured you can use "create-dm-tx.sh," which uses the in.sh file, to create a dm-tx volume under /dev/mapper/ as /dev/mapper/dm-tx. To figure out how to use Isotope and Yogurt features using ioctl calls, please refer to the library directory. You can destroy and remove dm-tx volume using "destroy-dm-tx.sh" in the src directory.


