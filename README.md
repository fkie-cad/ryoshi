# 猟師 [ryōshi]

These utilities enable forensic investigators to reliably detect and extract files, which have been hidden by rootkits. They are primarily designed for use on UNIX-based systems. The underlying principle, however, is platform-independent.

---

### How it works

All of the rootkits that we have found and analyzed during our research, share a similarity when it comes to file hiding: They don't touch the disk. Instead, they filter and manipulate the data flow from the disk to the user. This allows us to detect discrepancies between files present on disk and files shown in userspace applications.

```
ubuntu@Ubuntu:~$ ls -la | grep diamorphine
ubuntu@Ubuntu:~$ sudo fls -o 1054720 -r -p /dev/sda | grep diamorphine
r/r 664159:	home/ubuntu/diamorphine_secret_file
```
In the example above, we were of course aware of a hidden file and already knew its name. To find hidden files with arbitrary paths, an investigator has to iterate through all files present on disk and verify that they are visible in userspace. The utilities in this repository not only automate this task, but also assist in filtering false positives and extracting found files.

```
ubuntu@Ubuntu:~$ sudo ./scan /dev/sda3 / /usb/evidence
/dev/sda3 (26302MB) -> ext (1605633 inodes)
Hidden: /home/ubuntu/diamorphine_secret_file (664159)
Extracted: /usb/evidence/home/ubuntu/diamorphine_secret_file | MD5=(...) SHA1=(...)
```
During extraction, the utilities attempt to replicate the directory structure of the scanned file system and calculate hash sums for extracted files.

---

### Installation & Usage

We provide two different implementations: One is based on Brian Carrier's *The Sleuth Kit* and is written in C, while the other uses Dissect, a more modern forensic library written in Python. Both offer the same capabilities and should be chosen depending on the situation. In general: The C version is slightly faster, while the Python version is more portable. There are also small differences in supported file systems. Please view their respective documentations for details.

To be able to parse the disk, both implementations require root privileges. As arguments, they take:

**\<volume\>** The disk/volume/filesystem to be parsed. It has to contain a supported file system.<br>
**\<mount point\>** The path where the specified volume is mounted. If you want to parse an encrypted volume or other logical volume, use the corresponding mapper instead of specifying the volume directly (e.g. /dev/mapper/ubuntu--vg-ubuntu--lv).<br>
**\<extract path\>** A path where extracted files should be stored.



#### libtsk

Note, that statically compiling the libtsk can greatly reduce this utility's footprint.

```
sudo apt install libtsk-dev build-essential
git clone https://github.com/fkie-cad/ryoshi.git
cd ryoshi/tsk
make
```
```
sudo ./scan <volume> <mount point> <extract path>
sudo ./scan /dev/sda1 / /usb/evidence
```

#### dissect

Python >= 3.7 is required. The following instructions also assume *pip* is installed.


```
sudo pip install dissect
git clone https://github.com/fkie-cad/ryoshi.git
cd ryoshi/dissect
```
```
sudo python3 dscan.py <volume> <mount point> <extract path>
sudo python3 dscan.py /dev/sda1 / /usb/evidence
```

Using a tool like *PyInstaller* or *PyOxidizer* this utility can also be compiled into a single portable binary (the following example uses *PyInstaller*).

```
sudo apt install python3-venv binutils
python3 -m venv .venv
. .venv/bin/activate
pip install dissect pyinstaller
git clone https://github.com/fkie-cad/ryoshi.git
cd ryoshi/dissect
pyinstaller -F --clean --hidden-import pkgutil --hidden-import dissect --collect-submodules dissect dscan.py 
cd dist
sudo ./dscan <disk/volume/filesystem> <mount point> <extract path>
```
For more information on deployment and the differences between *PyInstaller* and *PyOxidizer* see the dissect [documentation](https://docs.dissect.tools/en/latest/tools/acquire.html#deployment).

---

### Limitations

Note, that due to the functions used, these utilities are currently unable to detect files hidden by application-level rootkits. Since these rootkits have become very rare, we believe this blind side to be mostly irrelevant in real-world scenarios. It should be possible to add support for specific applications if required.

Also note, that future rootkits may directly target these utilities to prevent detection.

---

### References

[The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/)
[Dissect](https://github.com/fox-it/dissect)
