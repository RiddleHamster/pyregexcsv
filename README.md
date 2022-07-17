# pyregexcsv

A python script to process unstructured files into a csv by regex extracting interesting features, including:

- Bitcoin addresses
- IPv4 addresses
- Email addresses

Pre-requisites:
[Tika](https://hub.docker.com/r/apache/tika)

Update the following before use...

Tika settings:

- TIKA_PORT
- TIKA_HOST

Example usage:

`python pyregexcsv.py folder out.csv`

CSV output after running extraction on recent Conti leaks: [csv](./out.csv)