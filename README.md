# kernel

```
nasm -f win64 entry.asm -o entry.o
clang -target x86_64-unknown-windows -nostdlib -Wl,-entry:efi_main -Wl,-subsystem:efi_application -fuse-ld=lld-link -o BOOTX64.EFI ./entry.o
```

```
CFLAGS='-target x86_64-unknown-windows 
        -ffreestanding 
        -fshort-wchar 
        -mno-red-zone 
        -Ipath/to/gnu-efi/inc -Ipath/to/gnu-efi/inc/x86_64 -Ipath/to/gnu-efi/inc/protocol'
LDFLAGS='-target x86_64-unknown-windows 
        -nostdlib 
        -Wl,-entry:efi_main 
        -Wl,-subsystem:efi_application 
        -fuse-ld=lld-link'
clang $CFLAGS -c -o hello.o hello.c
clang $CFLAGS -c -o data.o path/to/gnu-efi/lib/data.c
clang $LDFLAGS -o BOOTX64.EFI hello.o data.o
```


```
dd if=/dev/zero of=fat.img bs=1k count=1440
mformat -i fat.img -f 1440 ::
mmd -i fat.img ::/EFI
mmd -i fat.img ::/EFI/BOOT
mcopy -i fat.img BOOTX64.EFI ::/EFI/BOOT
```