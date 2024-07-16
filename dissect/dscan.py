
from dissect.target import container, filesystem, volume
from pathlib import Path
from os import listdir, path, geteuid
from sys import argv, exit

# Ignore /run since it may produce large numbers of false positives
IGNORE_RUN = True

def get_filesystem(path: str) -> str:
    try:
        return filesystem.open(open(path, "rb"))
    except:
        try: 
            return filesystem.open(volume.open(open(path, "rb")))
        except:
            disk = container.open(path)
            vol = volume.open(disk)
            vol_i = 0
            if len(vol.volumes) > 1:
                for v in vol.volumes:
                    print(f"[{vol.volumes.index(v)}] {v.name} ({v.size} bytes)")
                vol_i = int(input("$ "))
            return filesystem.open(vol.volumes[vol_i])

def is_visible(path: str) -> bool:
    p = Path(path)
    parent = p.parent.absolute()
    try:
        return p.name in listdir(parent)
    except:
        print("Failed to open", path)
        return True
    
def whitelist(path: str) -> bool:
    if path == "/":
        return True
    p = Path(path)
    if str(p.parents[-2]) == "/run" and IGNORE_RUN:
        return True
    return False

def extract_file(file: filesystem.FilesystemEntry, path: str) -> None:
    out = open(path, "wb")
    out.write(file.open().read())
    out.close()

def scan_filesystem(disk_path: str, mount_point: str, extract_path: str) -> int:
    try:
        fs = get_filesystem(disk_path)
        print("Filesystem:", fs.__type__)
    except:
        print(disk_path, "is not a valid volume/disk OR does not contain a supported filesystem")
        exit(-1)

    hidden_files = 0
    extract = []

    for _, dirs, files in fs.walk_ext("/", True, None, False):
        entries = dirs + files
        for entry in entries:
            full_path = path.join(mount_point, str(entry))
            if not is_visible(full_path) and not whitelist(full_path):
                out_path = path.join(extract_path, full_path[1:])
                print(f"Hidden: {full_path} ({entry.stat(False).st_ino})")
                hidden_files += 1
                extract.append([entry, out_path])

    for entry, out_path in extract:
        if entry.is_file(False):
            Path(out_path).parent.mkdir(parents=True, exist_ok=True)
            try:
                extract_file(entry, out_path)
                print(f"Extracted: {out_path} | MD5={entry.md5()} SHA256={entry.sha256()}")
            except:
                print("Failed to extract:", out_path)
        else:
            Path(out_path).mkdir(parents=True, exist_ok=True)
            print("Created:", out_path)
        
    return hidden_files

def main() -> int:
    if len(argv) >= 4:
        disk_path = argv[1]
        mount_point = argv[2]
        extract_path = argv[3]
    else:
        print(f"Usage: python {argv[0]} <disk/volume/filesystem> <mount point> <extract path>\nExample: python {argv[0]} /dev/sda / /evidence")
        exit(-1)

    if (geteuid() != 0):
        print("Root priviliges required to parse disk")
        exit(-1)

    hidden_files = scan_filesystem(disk_path, mount_point, extract_path)
    
    if hidden_files > 0:
        print(hidden_files, "hidden file(s) found")
    else:
        print("No hidden files found")
    
    return hidden_files

if __name__ == "__main__":
    exit(main())