# dm-tx
A Linux device mapper module that includes Gecko [USENIX FAST '13], Isotope [USENIX FAST '16], and Yogurt [ACM SoCC '16]. Notice that the code released here is not exactly the same version as the ones used in the papers, but is a reimplementation (some features may be missing or added).

Gecko layer implements the chained-logging design and redirects data blocks into the log. Isotope and Yogurt are built on top of the Gecko layer. Isotope takes care of ACID transactions over the block address space, and Yogurt enables fast but weakly consistent reads. Both Isotope and Yogurt features are accesible through ioctl calls.
