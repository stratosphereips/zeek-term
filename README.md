# Zeek-term

Zeek-term is a python program that reads several Zeek log files (conn.log, http.log, files.log, ssl.log, quick.log, dns.log, ntp.log) and prints all the lines sorted by time. It also adds colors so it is easier to analyze.


## Features

- Sorted logs from all the Zeek files.
- Adds background color.
- Adds foreground color.
- Adds a column with the name of the file that each log cames from.

## Usage

```python
python zeek-term.py --foreground --directory . |less -RS
```

- `--foreground` is to use foreground colors instead of background
- `--directory` is to set where the Zeek logs are
- `--filter-conn` is to filter all the conn.log lines which UID is in other Zeek file. Therefore, if a flow produced other log appart from the conn.log, then the conn.log one is ignored. This is good if you want to know which conn.log lines do not have a recognizable protocol and are interesting to see. 

# How it looks like
<img width="1908" alt="image" src="https://github.com/user-attachments/assets/706b266c-647d-45a4-98a0-d6c4c24320d4">

With --filter-conn
<img width="1887" alt="image" src="https://github.com/user-attachments/assets/9185f083-3d42-4f49-80ea-524f9e7efb33">

Without --foreground
<img width="1914" alt="image" src="https://github.com/user-attachments/assets/854c6816-18af-4155-8ec2-be256c09cd87">


# About

This tool was developed at the Stratosphere Laboratory at the Czech Technical University in Prague by Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz
