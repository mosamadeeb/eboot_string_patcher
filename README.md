# eboot_string_patcher
A small python script that updates string offsets in PS3 EBOOTs. Made with the purpose of allowing longer strings than what's originally allowed.

This script works by using an empty program segment (that must be originally in the eboot) to store the new strings inside, and update the string pointers in the eboot. The original strings are not removed, but they're basically unused because their pointers will be pointing to the new strings.



# Installing
This script uses [binary-reader](https://pypi.org/project/binary-reader/), so just use `pip install binary-reader` before running the script.

A compiled PyInstaller version is also provided in [the releases](https://github.com/SutandoTsukai181/eboot_string_patcher/releases).

# Support
This has been tested only on Ryu ga Gotoku Kenzan and Ishin. Please open a [new issue](https://github.com/SutandoTsukai181/eboot_string_patcher/issues/new) if you find any compatiblity problems with other PS3 games **which already have an empty segment**. This script works only with ELF files that conveniently have empty, unused program segments. Support for adding new segments might come in the future, if necessary.

# Usage
Requires a decrypted EBOOT.ELF, and a JSON file with the new strings, and file offsets of the original strings that will be replaced.

`python eboot_string_patcher.py [-h] [-j] [-v] [-u] [-s] [-a ALIGN_VALUE] [-e ENCODING] [json] [input] [output]`
## Arguments
```
positional arguments:
  json                  path to JSON file with the new strings (use --json-help for the format info)
  input                 path to input EBOOT.ELF
  output                path to output EBOOT.ELF

optional arguments:
  -h, --help            show this help message and exit
  -j, --json-help       show help info about the JSON file format and exit
  -v, --verbose         show info about each string entry that is patched
  -u, --update          skip adding strings that were added in a previous run (does not check for conflicts)
  -s, --safe            skip strings if their address was found multiple times (use this whenever the script breaks the eboot)
  -a ALIGN_VALUE, --align-value ALIGN_VALUE
                        force alignment of the segment before the empty segment to the value given
  -e ENCODING, --encoding ENCODING
                        set the encoding when reading the json and strings in the eboot (default is cp963; for Japanese text)
```
## JSON file format
The JSON file should have only 1 object called "strings", which contains an array of objects,
each with 2 elements: "text" and "address". "text" is the new string that will replace the old string at "address".
"address" must be a valid file offset in the input eboot, and can be either written in hex (as a string) or in decimal.

IMPORTANT: if an entry is removed from the JSON after running the script once, a clean EBOOT should be used.
Otherwise, running the script multiple times on the same EBOOT should not have any side effects.

Here's an example:
```json
{
    "strings": [
        {
            "text": "Test",
            "address": "0xC54E10"
        },
        {
            "text": "Test 2",
            "address": 12930592
        }
    ]
}
```
# Showcase
Just a proof of concept of what the script does.

An example of Kenzan's "Camera Control" settings. These were changed from "視点操作(縦)" and "視点操作(横)" to "Camera Control (Vertical)" and "Camera Control (Horizontal)", respectively. This is an increase from the original 12 bytes aligned to 16, to 26 bytes aligned to 32.

![image](https://user-images.githubusercontent.com/52977072/118058489-f6ae0c80-b396-11eb-8f97-f6098480f0f5.png)

# License
This project uses the MIT License, so feel free to include it in whatever you want.
