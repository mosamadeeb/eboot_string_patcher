# eboot_string_patcher
A small python script that updates string offsets in PS3 EBOOTs. Made with the purpose of allowing longer strings than what's originally allowed.

# Installing
This script uses [binary-reader](https://pypi.org/project/binary-reader/), so just use `pip install binary-reader` before running the script.

A compiled PyInstaller version is also provided in [the releases](https://github.com/SutandoTsukai181/eboot_string_patcher/releases).

# Support
This has been tested only on Ryu ga Gotoku Kenzan and Ishin. Please open a [new issue](https://github.com/SutandoTsukai181/eboot_string_patcher/issues/new) if you find any compatiblity problems with other PS3 games **if the game already has an empty segment**. This script works only with ELF files that conveniently have empty, unused program segments. Support for adding new segments might come in the future, if necessary.
